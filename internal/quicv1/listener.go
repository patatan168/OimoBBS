// UDPの実endpointを固定し、Retryで検証した接続だけを有限の接続actorへ渡す。
package quicv1

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Config はTLSと資源上限。AdmitはRetry成功後・TLS処理前に呼び出す。
type Config struct {
	TLSConfig      *tls.Config
	MaxConnections int
	// KeyUpdateAfterは検証用の鍵更新間隔。0では262144 packet。
	KeyUpdateAfter uint64
	Admit          func(context.Context, net.Addr) error
	// AllowUnvalidatedは未知接続のInitialとversion応答を暗号処理・送信前に制限する。
	// 既存接続には適用せず、falseなら応答も接続状態も作らない。
	AllowUnvalidated func(net.Addr) bool
}

// Listener はUDP socketを所有する。StopAcceptingは既存接続を維持し、Closeはすべて終了する。
type Listener struct {
	readFailure      error
	socket           *net.UDPConn
	packetConn       *ipv4.PacketConn
	cfg              Config
	token            cipher.AEAD
	mu               sync.Mutex
	connections      map[string]*Conn
	accepted         chan *Conn
	stopping         chan struct{}
	stopped          sync.Once
	closed           chan struct{}
	closeOnce        sync.Once
	workers          sync.WaitGroup
	gsoDisabled      atomic.Bool
	mtuFallbacks     atomic.Uint64
	sentPackets      atomic.Uint64
	lostPackets      atomic.Uint64
	sendCalls        atomic.Uint64
	preparedWrites   atomic.Uint64
	sendQueue        chan sendBurst
	sendDone         chan struct{}
	sendWorkers      sync.WaitGroup
	sendStopped      sync.Once
	destinationCache atomic.Pointer[destinationSnapshot]
}

// destinationSnapshot はkernelから借りた制御領域を複製し、宛先情報だけを一件保持する。
type destinationSnapshot struct {
	control []byte
	address *net.UDPAddr
}

// Listen はUDP socketに必要な宛先IP観測を設定してから受信を始める。
func Listen(socket *net.UDPConn, cfg Config) (*Listener, error) {
	if socket == nil || cfg.TLSConfig == nil || cfg.MaxConnections < 1 {
		return nil, errors.New("invalid QUIC listener configuration")
	}
	if cfg.KeyUpdateAfter == 0 {
		cfg.KeyUpdateAfter = 1 << 18
	}
	if cfg.KeyUpdateAfter < 8 || cfg.KeyUpdateAfter > 1<<18 {
		return nil, errors.New("invalid key update interval")
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	token, _ := cipher.NewGCM(block)
	v4err := ipv4.NewPacketConn(socket).SetControlMessage(ipv4.FlagDst, true)
	v6err := ipv6.NewPacketConn(socket).SetControlMessage(ipv6.FlagDst, true)
	if v4err != nil && v6err != nil && socket.LocalAddr().(*net.UDPAddr).IP.IsUnspecified() {
		return nil, errors.New("OS cannot observe wildcard UDP destination")
	}
	cfg.TLSConfig = cfg.TLSConfig.Clone()
	cfg.TLSConfig.MinVersion = tls.VersionTLS13
	l := &Listener{socket: socket, cfg: cfg, token: token, connections: make(map[string]*Conn), accepted: make(chan *Conn, cfg.MaxConnections), stopping: make(chan struct{}), closed: make(chan struct{}), sendQueue: make(chan sendBurst, 64), sendDone: make(chan struct{})}
	l.packetConn = ipv4.NewPacketConn(socket)
	l.workers.Add(1)
	l.sendWorkers.Add(1)
	go l.writeLoop()
	go l.readLoop()
	return l, nil
}
func (l *Listener) Addr() net.Addr { return l.socket.LocalAddr() }
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	select {
	case c := <-l.accepted:
		if c != nil {
			return c, nil
		}
		return nil, errClosed
	case <-l.stopping:
		l.mu.Lock()
		err := l.readFailure
		l.mu.Unlock()
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (l *Listener) StopAccepting() { l.stopped.Do(func() { close(l.stopping) }) }
func (l *Listener) Close() error   { l.stop(); l.finishClose(); return nil }

// stop は受信障害時にも受付と全接続を停止し、自分のworker終了を待たない。
func (l *Listener) stop() bool {
	stopped := false
	l.closeOnce.Do(func() {
		stopped = true
		l.StopAccepting()
		close(l.closed)
		l.socket.Close()
		l.mu.Lock()
		for _, c := range l.connections {
			c.cancel()
		}
		l.mu.Unlock()
	})
	return stopped
}
func (l *Listener) finishClose() {
	l.workers.Wait()
	l.sendStopped.Do(func() { close(l.sendDone) })
	l.sendWorkers.Wait()
}

func (l *Listener) readLoop() {
	defer l.workers.Done()
	defer func() {
		if l.stop() {
			go l.finishClose()
		}
	}()
	messages := make([]ipv4.Message, 32)
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, 4096)}
		messages[i].OOB = make([]byte, 256)
	}
	reader := ipv4.NewPacketConn(l.socket)
	for {
		n, err := reader.ReadBatch(messages, 0)
		if err != nil {
			l.mu.Lock()
			select {
			case <-l.closed:
			default:
				l.readFailure = err
			}
			l.mu.Unlock()
			return
		}
		for i := 0; i < n; i++ {
			m := &messages[i]
			peer, ok := m.Addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			l.dispatch(m.Buffers[0][:m.N], m.OOB[:m.NN], m.Flags, peer)
		}
	}
}

// dispatch は受信bufferを接続queueへコピーし、同じ実endpointのpacketだけを渡す。
func (l *Listener) dispatch(buffer, control []byte, flags int, peer *net.UDPAddr) {
	n := len(buffer)
	if flags&0x20 != 0 || n == 0 {
		return
	}
	local := l.destination(control)
	if local == nil {
		return
	}
	packet := buffer
	for len(packet) > 0 {
		header, err := parseHeader(packet)
		if err != nil || header.retry {
			break
		}
		l.mu.Lock()
		conn := l.connections[string(header.dcid)]
		l.mu.Unlock()
		if header.version == 0 {
			break
		}
		// 未対応versionを既存CIDへ送っても、認証失敗の集計や接続状態を変えない。
		if conn != nil && header.version != 1 || header.version == 1 && header.space == spaceInitial && n < 1200 {
			break
		}
		if conn == nil && n >= 1200 && (header.version != 1 || header.space == spaceInitial) && l.cfg.AllowUnvalidated != nil && !l.cfg.AllowUnvalidated(peer) {
			break
		}
		if conn == nil && header.version != 1 {
			if n >= 1200 {
				l.versionNegotiation(header, peer, local)
			}
			break
		}
		if conn == nil && header.space == spaceInitial && n >= 1200 {
			conn = l.initial(header, peer, local)
		}
		if conn != nil && conn.peer.Port == peer.Port && conn.peer.Zone == peer.Zone && conn.peer.IP.Equal(peer.IP) && conn.local.IP.Equal(local.IP) && conn.local.Port == local.Port {
			event := receivedPacket{data: append([]byte(nil), packet[:header.size]...), header: header, at: time.Now()}
			select {
			case conn.incoming <- event:
			default:
			}
		}
		if header.size <= 0 || header.size >= len(packet) {
			break
		}
		packet = packet[header.size:]
	}
}

func (l *Listener) destination(oob []byte) *net.UDPAddr {
	if cached := l.destinationCache.Load(); cached != nil && bytes.Equal(oob, cached.control) {
		return cached.address
	}
	bound := l.socket.LocalAddr().(*net.UDPAddr)
	ip := bound.IP
	var v4 ipv4.ControlMessage
	if v4.Parse(oob) == nil && v4.Dst != nil {
		ip = v4.Dst
	}
	var v6 ipv6.ControlMessage
	if v6.Parse(oob) == nil && v6.Dst != nil {
		ip = v6.Dst
	}
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	address := &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: bound.Port, Zone: bound.Zone}
	if len(oob) <= 256 {
		l.destinationCache.Store(&destinationSnapshot{control: bytes.Clone(oob), address: address})
	}
	return address
}
func (l *Listener) send(data []byte, peer, local *net.UDPAddr) error {
	var oob []byte
	if local.IP.To4() != nil {
		oob = (&ipv4.ControlMessage{Src: local.IP}).Marshal()
	} else {
		oob = (&ipv6.ControlMessage{Src: local.IP}).Marshal()
	}
	l.sendCalls.Add(1)
	_, _, err := l.socket.WriteMsgUDP(data, oob, peer)
	return err
}

// sendBatch は独立datagramをsendmmsg対応OSで一括送信する。非対応OSは下位実装が逐次送る。
func (l *Listener) sendBatch(packets [][]byte, peer, local *net.UDPAddr) error {
	return l.sendBatchOwned(packets, nil, peer, local)
}

func (l *Listener) versionNegotiation(h packetHeader, peer, local *net.UDPAddr) {
	out := binary.BigEndian.AppendUint32([]byte{0xc0}, 0)
	out = append(out, byte(len(h.scid)))
	out = append(out, h.scid...)
	out = append(out, byte(len(h.dcid)))
	out = append(out, h.dcid...)
	out = binary.BigEndian.AppendUint32(out, 1)
	_ = l.send(out, peer, local)
}

// retryToken はsource endpoint・期限・original DCID・Retry SCIDをAEADで結ぶ。
func (l *Listener) retryToken(peer *net.UDPAddr, original, id []byte) []byte {
	plain := binary.BigEndian.AppendUint64(nil, uint64(time.Now().Unix()))
	plain = append(plain, byte(len(original)))
	plain = append(plain, original...)
	plain = append(plain, id...)
	nonce := make([]byte, l.token.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}
	return l.token.Seal(nonce, nonce, plain, []byte(peer.String()))
}
func (l *Listener) verifyToken(peer *net.UDPAddr, dcid, token []byte) ([]byte, bool) {
	n := l.token.NonceSize()
	if len(token) < n+l.token.Overhead()+17 {
		return nil, false
	}
	plain, err := l.token.Open(nil, token[:n], token[n:], []byte(peer.String()))
	if err != nil || len(plain) < 17 {
		return nil, false
	}
	at := int64(binary.BigEndian.Uint64(plain))
	now := time.Now().Unix()
	length := int(plain[8])
	if at > now || now-at > 10 || length > 20 || len(plain) != 9+length+connectionIDSize || !bytes.Equal(plain[9+length:], dcid) {
		return nil, false
	}
	return append([]byte(nil), plain[9:9+length]...), true
}
func (l *Listener) initial(h packetHeader, peer, local *net.UDPAddr) *Conn {
	select {
	case <-l.stopping:
		return nil
	default:
	}
	if len(h.dcid) < 8 {
		return nil
	}
	original, verified := l.verifyToken(peer, h.dcid, h.token)
	if !verified {
		if len(h.token) > 0 {
			return nil
		}
		id := make([]byte, connectionIDSize)
		if _, err := rand.Read(id); err != nil {
			return nil
		}
		out := binary.BigEndian.AppendUint32([]byte{0xf0}, 1)
		out = append(out, byte(len(h.scid)))
		out = append(out, h.scid...)
		out = append(out, byte(len(id)))
		out = append(out, id...)
		out = append(out, l.retryToken(peer, h.dcid, id)...)
		out = append(out, retryIntegrity(h.dcid, out)...)
		_ = l.send(out, peer, local)
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return nil
	default:
	}
	if c := l.connections[string(h.dcid)]; c != nil {
		return c
	}
	if len(l.connections) >= l.cfg.MaxConnections {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	if l.cfg.Admit != nil {
		if err := l.cfg.Admit(ctx, peer); err != nil {
			cancel()
			return nil
		}
	}
	c, err := newConn(l, ctx, cancel, peer, local, h.dcid, h.scid, original)
	if err != nil {
		cancel()
		return nil
	}
	l.connections[string(c.id)] = c
	l.workers.Add(1)
	go func() {
		defer l.workers.Done()
		c.run()
		l.mu.Lock()
		delete(l.connections, string(c.id))
		l.mu.Unlock()
	}()
	return c
}
