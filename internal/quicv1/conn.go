// 接続ごとの単一actorがTLS・packet番号・送信queue・flow controlを所有する。
package quicv1

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type receivedPacket struct {
	data   []byte
	header packetHeader
	at     time.Time
}
type queuedFrame struct {
	space      int
	data       []byte
	refs       []*sendBlock
	unreliable bool
}

// Conn は検証済みendpointを固定したQUIC接続。制御状態はrun以外から直接変更しない。
type Conn struct {
	listener                                                          *Listener
	ctx                                                               context.Context
	cancel                                                            context.CancelFunc
	peer, local                                                       *net.UDPAddr
	id, peerID, originalID                                            []byte
	tls                                                               *tls.QUICConn
	stateMu                                                           sync.Mutex
	tlsState                                                          tls.ConnectionState
	spaces                                                            [3]numberSpace
	recovery                                                          recovery
	incoming                                                          chan receivedPacket
	commands                                                          chan any
	bidi, uni                                                         chan *Stream
	streams                                                           map[uint64]*Stream
	pending                                                           []queuedFrame
	pendingBase                                                       []queuedFrame
	blocked                                                           []*writeRequest
	queuedBytes                                                       int
	handshakeDone, parametersReceived, accepted                       bool
	peerMaxData, txTotal, receiveTotal, receiveConsumed, receiveLimit uint64
	peerBidiLocal, peerBidiRemote, peerUni                            uint64
	peerMaxUni, localNextUni                                          uint64
	maxBidi, maxUni, nextPeerBidi, nextPeerUni                        uint64
	retired                                                           [2]uint64
	finished                                                          [2]map[uint64]bool
	localCredit                                                       [2]uint64
	lastActivity, started, nextPace                                   time.Time
	keyPhase                                                          bool
	readKeyPhase                                                      bool
	previousRead                                                      *packetKeys
	previousReadUntil                                                 time.Time
	pathResponseAt                                                    time.Time
	pathResponseCredit                                                int
	nextRead                                                          *packetKeys
	drainers                                                          []chan struct{}
	peerCIDs                                                          map[uint64]peerCID
	peerCIDSequence, peerRetireFloor                                  uint64
	readPhaseStart                                                    uint64
	readPhaseAcknowledged                                             bool
	decryptionFailures                                                uint64
	writeKeyPackets                                                   uint64
	batching                                                          bool
	batch                                                             []*packetBuffer
	cipherBatch                                                       *cipherBlock
	padding                                                           [1500]byte
	headerBuffer                                                      [64]byte
	readBuffer                                                        [1500]byte
	mtu, peerMaxUDP, mtuFailures                                      int
	mtuProbePending                                                   bool
	mtuProbeAt                                                        time.Time
	chunkSize                                                         atomic.Int32
	mtuSnapshot                                                       atomic.Int32
	readProgress                                                      atomic.Uint64
	consumeWake                                                       chan struct{}
	largeLosses                                                       int
	lastLargeAck, lastSmallAck, firstLargeLoss                        time.Time
	writePhaseFirst                                                   uint64
	writePhaseAcked                                                   bool
	idleTimeout                                                       time.Duration
	nextWriteExpiry                                                   time.Time
	statsWindow                                                       atomic.Int64
	statsRTT                                                          atomic.Int64
}

func newConn(l *Listener, ctx context.Context, cancel context.CancelFunc, peer, local *net.UDPAddr, id, peerID, original []byte) (*Conn, error) {
	c := &Conn{listener: l, ctx: ctx, cancel: cancel, peer: peer, local: local, id: append([]byte(nil), id...), peerID: append([]byte(nil), peerID...), originalID: original, recovery: newRecovery(), incoming: make(chan receivedPacket, 128), commands: make(chan any, 32), bidi: make(chan *Stream, 32), uni: make(chan *Stream, 3), streams: make(map[uint64]*Stream), receiveLimit: 256 << 10, maxBidi: 32, maxUni: 3, started: time.Now()}
	c.consumeWake = make(chan struct{}, 1)
	c.lastActivity = c.started
	c.idleTimeout = 30 * time.Second
	c.setMTU(1200)
	c.peerMaxUDP = 1452
	c.peerCIDs = map[uint64]peerCID{0: {id: append([]byte(nil), peerID...)}}
	c.localCredit = [2]uint64{32, 3}
	c.finished = [2]map[uint64]bool{make(map[uint64]bool), make(map[uint64]bool)}
	for i := range c.spaces {
		c.spaces[i] = newNumberSpace()
	}
	read, write, err := initialKeys(id)
	if err != nil {
		return nil, err
	}
	c.spaces[spaceInitial].read = read
	c.spaces[spaceInitial].write = write
	c.tls = tls.QUICServer(&tls.QUICConfig{TLSConfig: l.cfg.TLSConfig, ClientHelloInfoConn: &endpointConn{local: local, peer: peer}})
	c.tls.SetTransportParameters(c.parameters())
	if err := c.tls.Start(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Conn) Context() context.Context { return c.ctx }
func (c *Conn) LocalAddr() net.Addr      { return c.local }
func (c *Conn) RemoteAddr() net.Addr     { return c.peer }
func (c *Conn) ConnectionState() tls.ConnectionState {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.tlsState
}
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error)    { return c.accept(ctx, c.bidi) }
func (c *Conn) AcceptUniStream(ctx context.Context) (*Stream, error) { return c.accept(ctx, c.uni) }
func (c *Conn) accept(ctx context.Context, queue <-chan *Stream) (*Stream, error) {
	select {
	case s := <-queue:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, errClosed
	}
}
func (c *Conn) OpenUniStream(ctx context.Context) (*Stream, error) {
	cmd := streamCommand{kind: commandOpenUni, opened: make(chan *Stream, 1), done: make(chan error, 1)}
	select {
	case c.commands <- cmd:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, errClosed
	}
	select {
	case s := <-cmd.opened:
		return s, nil
	case err := <-cmd.done:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, errClosed
	}
}

// Drain は既にqueueへ確定したデータのACKを待つ。呼出元は先に新規書込を止める。
func (c *Conn) Drain(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case c.commands <- drainRequest{done}:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return errClosed
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return errClosed
	}
}

type drainRequest struct{ done chan struct{} }

func (c *Conn) notifyDrained() {
	if len(c.drainers) == 0 {
		return
	}
	if len(c.pending) > 0 || len(c.blocked) > 0 {
		return
	}
	for i := range c.spaces {
		s := &c.spaces[i]
		if len(s.sent) > 0 {
			return
		}
	}
	for _, ch := range c.drainers {
		close(ch)
	}
	c.drainers = nil
}
func (c *Conn) CloseWithError(code uint64, reason string) error {
	return c.command(streamCommand{kind: commandClose, code: code})
}
func (c *Conn) command(cmd streamCommand) error {
	select {
	case c.commands <- cmd:
		return nil
	case <-c.ctx.Done():
		return errClosed
	}
}

// consumed は接続全体で32KiB消費するごとにactorを一度起こす。
// streamごとの閾値では、多数のstreamが各閾値未満を消費した状態でMAX_DATAが尽きる。
func (c *Conn) consumed(n int) {
	if c.readProgress.Add(uint64(n)) >= 32<<10 {
		select {
		case c.consumeWake <- struct{}{}:
		default:
		}
	}
}
func (c *Conn) updateConsumed() {
	c.readProgress.Swap(0)
	for _, s := range c.streams {
		s.mu.Lock()
		consumed := s.readConsumed
		s.mu.Unlock()
		c.creditConsumed(s, consumed)
	}
}

func (c *Conn) run() {
	defer c.cancel()
	defer c.releaseBuffers()
	defer c.tls.Close()
	defer func() {
		for _, s := range c.streams {
			s.fail(errClosed)
		}
	}()
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	for {
		if err := c.drainCommands(); err != nil {
			if !errors.Is(err, errClosed) {
				c.abort(err)
			}
			return
		}
		if c.handshakeDone && c.queuedBytes > 0 && c.queuedBytes < 1100 && len(c.pending) > 0 && c.pending[0].space == spaceApplication {
			runtime.Gosched()
			if err := c.drainCommands(); err != nil {
				if !errors.Is(err, errClosed) {
					c.abort(err)
				}
				return
			}
		}
		now := time.Now()
		c.expireReadKeys(now)
		if now.Sub(c.lastActivity) > max(c.idleTimeout, 3*c.recovery.basePTO()) || !c.handshakeDone && now.Sub(c.started) > 5*time.Second {
			return
		}
		if err := c.flush(now); err != nil {
			return
		}
		c.notifyDrained()
		delay := c.nextWake(now)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
		select {
		case <-c.consumeWake:
			c.updateConsumed()
		case p := <-c.incoming:
			if err := c.receiveAvailable(p); err != nil {
				if !errors.Is(err, errClosed) {
					c.abort(err)
				}
				return
			}
		case command := <-c.commands:
			if err := c.handleCommand(command); err != nil {
				if !errors.Is(err, errClosed) {
					c.abort(err)
				}
				return
			}
		case <-timer.C:
			c.onTimer(time.Now())
		case <-c.ctx.Done():
			return
		}
	}
}

// receiveAvailable は既に届いた最大16packetをまとめ、送信と期限timerの再設定を一巡にする。
// 待機や無制限なdrainは行わず、アプリ書込と取消の処理機会も残す。
func (c *Conn) receiveAvailable(first receivedPacket) error {
	if err := c.receivePacket(first); err != nil {
		return err
	}
	for range 15 {
		select {
		case p := <-c.incoming:
			if err := c.receivePacket(p); err != nil {
				return err
			}
		default:
			return nil
		}
	}
	return nil
}
func (c *Conn) receivePacket(p receivedPacket) error {
	s := &c.spaces[p.header.space]
	if s.read == nil {
		return nil
	}
	expected := uint64(0)
	if s.received {
		expected = s.largestReceived + 1
	}
	data, pn, first, err := s.read.openPacketInto(c.readBuffer[:0], p.data, p.header.pnOffset, expected)
	var authenticatedError *transportError
	if errors.As(err, &authenticatedError) {
		return err
	}
	if err == nil && p.header.space == spaceApplication && ((first&4) != 0) != c.readKeyPhase {
		return protocolError(0xe, 0, "key phase mismatch")
	}
	if err != nil && p.header.space == spaceApplication && c.handshakeDone {
		if c.nextRead == nil {
			c.nextRead, _ = s.read.next()
		}
		if c.nextRead != nil {
			data, pn, first, err = c.nextRead.openPacketInto(c.readBuffer[:0], p.data, p.header.pnOffset, expected)
			if errors.As(err, &authenticatedError) {
				return err
			}
			if err == nil {
				if c.readPhaseStart != 0 && !c.readPhaseAcknowledged && c.keyPhase == c.readKeyPhase {
					return protocolError(0xe, 0, "key update before current phase acknowledgment")
				}
				if pn <= s.largestReceived || ((first&4) != 0) == c.readKeyPhase {
					return protocolError(0xe, 0, "invalid key update phase")
				}
				c.previousRead = s.read
				c.previousReadUntil = time.Now().Add(3 * c.recovery.basePTO())
				s.read = c.nextRead
				c.nextRead = nil
				c.readKeyPhase = !c.readKeyPhase
				c.readPhaseStart = pn
				c.readPhaseAcknowledged = false
				// RFC9001 6.1: 新しい受信phaseをACKする前に、送信側も新しい鍵へ進める。
				if c.keyPhase != c.readKeyPhase {
					write, updateErr := s.write.next()
					if updateErr != nil {
						return updateErr
					}
					s.write = write
					c.keyPhase = c.readKeyPhase
					c.writeKeyPackets = 0
					c.writePhaseFirst = s.next
					c.writePhaseAcked = false
					c.queue(spaceApplication, []byte{1})
				}
			}
		}
		if err != nil && c.previousRead != nil && time.Now().Before(c.previousReadUntil) {
			data, pn, first, err = c.previousRead.openPacketInto(c.readBuffer[:0], p.data, p.header.pnOffset, expected)
			if err == nil && pn >= c.readPhaseStart {
				return protocolError(0xe, 0, "previous key packet number")
			}
		}
	}
	if err != nil {
		c.decryptionFailures++
		if c.decryptionFailures >= 1024 {
			return protocolError(0xf, 0, "packet authentication limit")
		}
		var transport *transportError
		if errors.As(err, &transport) {
			return err
		}
		return nil
	}
	if pn > maxVarint {
		return protocolError(0xa, 0, "packet number overflow")
	}
	if !s.receive(pn, p.at) {
		return nil
	}
	c.lastActivity = p.at
	ackEliciting, err := c.frames(p.header.space, data, p.at)
	if err != nil {
		return err
	}
	if ackEliciting {
		s.ackPending = true
		s.ackCount++
		s.ackAt = p.at.Add(25 * time.Millisecond)
		if p.header.space != spaceApplication || s.ackCount >= 2 {
			s.ackAt = p.at
		}
	}
	if p.header.space == spaceHandshake && c.spaces[spaceInitial].read != nil {
		c.discardSpace(spaceInitial)
	}
	if c.handshakeDone && c.spaces[spaceHandshake].read != nil {
		c.discardSpace(spaceHandshake)
	}
	c.processBlocked()
	c.statsWindow.Store(int64(c.recovery.cwnd))
	c.statsRTT.Store(int64(c.recovery.smoothed))
	return nil
}
func (c *Conn) abort(err error) {
	code := uint64(1)
	frame := uint64(0)
	var e *transportError
	if errors.As(err, &e) {
		code = e.code
		frame = e.frame
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		code = 0x100 + uint64(alert)
	}
	space := spaceApplication
	if c.spaces[space].write == nil {
		space = spaceHandshake
	}
	if c.spaces[space].write == nil {
		space = spaceInitial
	}
	out := appendVarint(nil, 0x1c)
	out = appendVarint(out, code)
	out = appendVarint(out, frame)
	out = append(out, 0)
	_ = c.transmit(space, out, nil, time.Now(), true)
}

// queue は不変なframe bufferの所有権を受け取る。呼出元は以後dataを書き換えない。
func (c *Conn) queue(space int, data []byte) { c.queueRefs(space, data, nil) }
func (c *Conn) queueRefs(space int, data []byte, refs []*sendBlock) {
	c.queueFrame(space, data, refs, false)
}

// queueFrame は再送可能なframeと一度だけ応答するframeを同じ有限枠へ入れる。
func (c *Conn) queueFrame(space int, data []byte, refs []*sendBlock, unreliable bool) {
	if c.queuedBytes+len(data) > 512<<10 || len(c.pending) >= 4096 {
		releaseRefs(refs)
		c.cancel()
		return
	}
	if len(data) == 0 {
		releaseRefs(refs)
		return
	}
	if len(c.pending) == cap(c.pending) && cap(c.pendingBase) > len(c.pending) {
		n := copy(c.pendingBase, c.pending)
		clear(c.pendingBase[n:])
		c.pending = c.pendingBase[:n]
	}
	previousCapacity := cap(c.pending)
	c.pending = append(c.pending, queuedFrame{space: space, data: data, refs: refs, unreliable: unreliable})
	if cap(c.pending) != previousCapacity {
		c.pendingBase = c.pending[:cap(c.pending)]
	}
	c.queuedBytes += len(data)
}

// consumePending は送信済みslotの参照を切り、空になったqueueの領域を次の応答へ再利用する。
// frame本文と再送の所有権は呼出元が移し、この処理では解放しない。
func (c *Conn) consumePending(n int) {
	clear(c.pending[:n])
	c.pending = c.pending[n:]
	if len(c.pending) == 0 {
		c.pending = c.pendingBase[:0]
	}
}
func (c *Conn) discardSpace(index int) {
	s := &c.spaces[index]
	for _, p := range s.sent {
		c.recovery.inFlight = max(0, c.recovery.inFlight-p.size)
		releaseRefs(p.refs)
	}
	*s = newNumberSpace()
	pending := c.pending[:0]
	for _, p := range c.pending {
		if p.space != index {
			pending = append(pending, p)
		} else {
			c.queuedBytes -= len(p.data)
			releaseRefs(p.refs)
		}
	}
	clear(c.pending[len(pending):])
	c.pending = pending
}

// endpointConn はTLSの証明書選択へ実endpointを渡し、QUIC I/Oは接続actorだけが行う。
type endpointConn struct{ local, peer net.Addr }

func (e *endpointConn) LocalAddr() net.Addr              { return e.local }
func (e *endpointConn) RemoteAddr() net.Addr             { return e.peer }
func (e *endpointConn) Read([]byte) (int, error)         { return 0, errors.ErrUnsupported }
func (e *endpointConn) Write([]byte) (int, error)        { return 0, errors.ErrUnsupported }
func (e *endpointConn) Close() error                     { return nil }
func (e *endpointConn) SetDeadline(time.Time) error      { return nil }
func (e *endpointConn) SetReadDeadline(time.Time) error  { return nil }
func (e *endpointConn) SetWriteDeadline(time.Time) error { return nil }

// drainCommands は到着済みの書込を一つの送信burstへまとめ、queueの枯渇まで待たない。
func (c *Conn) drainCommands() error {
	for range 32 {
		select {
		case <-c.consumeWake:
			c.updateConsumed()
		case command := <-c.commands:
			if err := c.handleCommand(command); err != nil {
				return err
			}
		default:
			return nil
		}
	}
	return nil
}

// releaseBuffers は停止時にも全所有権を一度だけ返す。未受理のchannel要素はGCへ任せる。
func (c *Conn) releaseBuffers() {
	for _, p := range c.pending {
		releaseRefs(p.refs)
	}
	for i := range c.spaces {
		for _, p := range c.spaces[i].sent {
			releaseRefs(p.refs)
		}
	}
	for _, request := range c.blocked {
		request.block.release()
	}
}
