// HTTP/3制御streamと要求の寿命を管理する。UDPを所有するQUIC listenerは呼出元が渡す。
package http3native

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"oimobbs/internal/quicv1"
)

const (
	maxConnectionRequests = 32
	maxServerRequests     = 256

	errNoError         = 0x100
	errGeneral         = 0x101
	errInternal        = 0x102
	errCritical        = 0x104
	errFrameUnexpected = 0x105
	errExcessive       = 0x107
	errSettings        = 0x109
	errMissingSettings = 0x10a
	errRejected        = 0x10b
	errCancelled       = 0x10c
	errIncomplete      = 0x10d
	errMessage         = 0x10e
	errQPACK           = 0x200
)

// Server は同じnet/http handlerを使用する、独自HTTP/3サーバー。
// HTTPの業務処理・認可・本文上限はHTTP.Serverのhandlerが担う。
// header読取からhandler終了まで接続32件・server全体256件に制限し、取消後に残る処理も数える。
type Server struct {
	HTTP           *http.Server
	mu             sync.Mutex
	closing        bool
	listener       *quicv1.Listener
	connections    map[*connection]bool
	wg             sync.WaitGroup
	activeRequests int // muで保護し、接続終了後もhandlerが戻るまでは数える。
}
type connection struct {
	server         *Server
	quic           *quicv1.Conn
	qpack          *QPACK
	control        *quicv1.Stream
	ctx            context.Context
	tlsState       tls.ConnectionState
	remoteAddr     string
	mu             sync.Mutex
	seen           map[uint64]bool
	settings       bool
	peerFieldLimit uint64
	nextRequest    uint64
	shutdownOnce   sync.Once
	controlBudget  atomic.Int64
	unknownUni     int
	requests       sync.WaitGroup
	activeRequests int // server.muで保護する。
}

// Serve はlistenerから検証済み接続を受ける。CloseまたはShutdown後は再使用できない。
func (s *Server) Serve(l *quicv1.Listener) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return http.ErrServerClosed
	}
	s.listener = l
	s.connections = make(map[*connection]bool)
	s.mu.Unlock()
	for {
		q, err := l.Accept(context.Background())
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return http.ErrServerClosed
			}
			return err
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			_ = q.CloseWithError(errRejected, "")
			continue
		}
		c := &connection{server: s, quic: q, seen: make(map[uint64]bool), peerFieldLimit: 1<<62 - 1}
		s.connections[c] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go func() { defer s.wg.Done(); c.serve(); s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
	}
}
func (c *connection) serve() {
	c.controlBudget.Store(initialControlBudget)
	defer c.quic.CloseWithError(errNoError, "")
	c.tlsState = c.quic.ConnectionState()
	c.remoteAddr = c.quic.RemoteAddr().String()
	if c.tlsState.NegotiatedProtocol != "h3" {
		c.fail(errGeneral)
		return
	}
	defer c.requests.Wait()
	c.ctx = context.WithValue(c.quic.Context(), http.LocalAddrContextKey, c.quic.LocalAddr())
	if h := c.server.HTTP; h.ConnContext != nil {
		c.ctx = h.ConnContext(c.ctx, &endpoint{conn: c.quic})
	}
	control, err := c.quic.OpenUniStream(c.ctx)
	if err != nil {
		return
	}

	c.qpack = newQPACK(nil, nil)
	c.qpack.openStream = func(kind byte) (*quicv1.Stream, error) {
		stream, err := c.quic.OpenUniStream(c.ctx)
		if err != nil {
			return nil, err
		}
		_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err = stream.Write([]byte{kind}); err != nil {
			return nil, err
		}
		return stream, nil
	}
	settings := append(integer(1), integer(4096)...)
	settings = append(settings, integer(6)...)
	settings = append(settings, integer(16<<10)...)
	settings = append(settings, integer(7)...)
	settings = append(settings, integer(16)...)
	_ = control.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err = control.Write(append([]byte{0}, frame(4, settings)...)); err != nil {
		return
	}

	c.mu.Lock()
	c.control = control
	c.mu.Unlock()
	go c.acceptUni()
	for {
		stream, err := c.quic.AcceptStream(c.ctx)
		if err != nil {
			return
		}
		c.server.mu.Lock()
		if c.server.closing {
			c.server.mu.Unlock()
			stream.CancelRead(errRejected)
			stream.CancelWrite(errRejected)
			continue
		}
		if c.activeRequests >= maxConnectionRequests || c.server.activeRequests >= maxServerRequests {
			c.server.mu.Unlock()
			c.fail(errExcessive)
			return
		}
		c.activeRequests++
		c.server.activeRequests++
		c.mu.Lock()
		c.nextRequest = max(c.nextRequest, stream.ID()+4)
		c.mu.Unlock()
		c.requests.Add(1)
		c.server.mu.Unlock()
		go func() { defer c.releaseRequest(); c.request(stream) }()
	}
}

// releaseRequest は取消済みhandlerも終了まで枠に保持し、接続の開き直しによる上限回避を防ぐ。
func (c *connection) releaseRequest() {
	c.server.mu.Lock()
	c.activeRequests--
	c.server.activeRequests--
	c.server.mu.Unlock()
	c.requests.Done()
}
func (c *connection) fail(code uint64) { _ = c.quic.CloseWithError(code, "") }
func (c *connection) acceptUni() {
	for {
		stream, err := c.quic.AcceptUniStream(c.ctx)
		if err != nil {
			return
		}
		go c.uni(stream)
	}
}
func (c *connection) uni(stream *quicv1.Stream) {
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, err := readInteger(stream)
	if err != nil {
		c.fail(errGeneral)
		return
	}
	if kind == 1 { // clientがpush streamを開始することは許可しない。
		c.fail(0x103)
		return
	}
	if kind != 0 && kind != 2 && kind != 3 {
		c.mu.Lock()
		c.unknownUni++
		exhausted := c.unknownUni > 16
		c.mu.Unlock()
		if exhausted {
			c.fail(errExcessive)
			return
		}
		stream.CancelRead(errCancelled)
		return
	}
	c.mu.Lock()
	seen := c.seen[kind]
	c.seen[kind] = true
	c.mu.Unlock()
	if seen {
		c.fail(0x103)
		return
	}
	if kind != 0 {
		_ = stream.SetReadDeadline(time.Time{})
	}
	budget := &controlReader{conn: c, reader: stream}
	switch kind {
	case 0:
		err = c.readControl(budget)
	case 2:
		err = c.qpack.readEncoder(budget)
	case 3:
		err = c.qpack.readDecoder(budget)
	}
	if err != nil && c.ctx.Err() == nil {
		var bounded *connectionError
		if errors.As(err, &bounded) {
			c.fail(bounded.code)
			return
		}
		var reset *quicv1.StreamError
		if errors.Is(err, io.EOF) || errors.As(err, &reset) {
			c.fail(errCritical)
			return
		}
		if kind == 2 {
			c.fail(0x201)
		} else if kind == 3 {
			c.fail(0x202)
		} else {
			var h *connectionError
			if errors.As(err, &h) {
				c.fail(h.code)
			} else {
				c.fail(errCritical)
			}
		}
	}
}

type connectionError struct{ code uint64 }

func (e *connectionError) Error() string { return "HTTP/3 connection error" }
func (c *connection) readControl(stream io.Reader) error {
	first := true
	for {
		kind, n, err := readFrame(stream)
		if err != nil {
			return err
		}
		if first && kind != 4 {
			return &connectionError{errMissingSettings}
		}
		first = false
		switch kind {
		case 4:
			c.mu.Lock()
			duplicate := c.settings
			c.settings = true
			c.mu.Unlock()
			if duplicate {
				return &connectionError{errFrameUnexpected}
			}
			data, err := bounded(stream, n, 4096)
			if err != nil {
				return &connectionError{errSettings}
			}
			if err = c.settingsFrame(data); err != nil {
				return &connectionError{errSettings}
			}
			if d, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
				_ = d.SetReadDeadline(time.Time{})
			}
		case 7, 0xd: // MAX_PUSH_IDは受けるがpushを発行しない。client GOAWAYはserver push IDを示す。pushは提供しない。
			data, err := bounded(stream, n, 8)
			if err != nil {
				return err
			}
			r := bytesReader(data)
			if _, err = readInteger(r); err != nil || r.Len() != 0 {
				return &connectionError{0x106}
			}
		case 0, 1, 2, 3, 5, 6, 8, 9:
			return &connectionError{errFrameUnexpected}
		default:
			if n > 16<<10 {
				return &connectionError{errExcessive}
			}
			if _, err = io.CopyN(io.Discard, stream, int64(n)); err != nil {
				return err
			}
		}
	}
}
func (c *connection) settingsFrame(data []byte) error {
	r := bytesReader(data)
	seen := map[uint64]bool{}
	var capacity, blocked uint64
	for r.Len() > 0 {
		id, err := readInteger(r)
		if err != nil {
			return err
		}
		v, err := readInteger(r)
		if err != nil || seen[id] {
			return errors.New("duplicate/truncated setting")
		}
		seen[id] = true
		switch id {
		case 1:
			capacity = v
		case 7:
			blocked = v
		case 6:
			c.mu.Lock()
			c.peerFieldLimit = v
			c.mu.Unlock()
		case 0, 2, 3, 4, 5:
			return errors.New("HTTP/2 setting")
		case 8, 0x33:
			if v > 1 {
				return errors.New("boolean setting")
			}
		}
	}
	return c.qpack.configure(capacity, blocked)
}

// Shutdown は新規接続・要求を止め、実行中handlerと送信ACKを期限内に待つ。
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	l := s.listener
	connections := make([]*connection, 0, len(s.connections))
	for c := range s.connections {
		connections = append(connections, c)
	}
	s.mu.Unlock()
	if l != nil {
		l.StopAccepting()
	}
	done := make(chan struct{})
	go func() {
		for _, c := range connections {
			c.shutdownOnce.Do(func() {
				c.mu.Lock()
				control, next := c.control, c.nextRequest
				c.mu.Unlock()
				if control != nil {
					deadline := time.Now().Add(5 * time.Second)
					if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
						deadline = d
					}
					_ = control.SetWriteDeadline(deadline)
					_, _ = control.Write(frame(7, integer(next)))
				}
			})
			c.requests.Wait()
			_ = c.quic.Drain(ctx)
			_ = c.quic.CloseWithError(errNoError, "")
		}
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		_ = s.Close()
		return ctx.Err()
	}
}

// Close は実行中の全接続を中断して待受を解放する。
func (s *Server) Close() error {
	s.mu.Lock()
	s.closing = true
	l := s.listener
	s.mu.Unlock()
	if l != nil {
		return l.Close()
	}
	return nil
}
