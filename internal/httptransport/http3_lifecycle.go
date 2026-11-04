// HTTP/3だけの停止時にもTCPを継続し、正常停止では受理済み応答とACKを待つ。
package httptransport

import (
	"context"
	"errors"
	"net/http"
)

// Serve は確保済みUDPを処理する。終了後はTCP側のHTTP/3広告を止める。
func (h *HTTP3) Serve() error {
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		return http.ErrServerClosed
	}
	h.started.Store(true)
	h.active.Store(true)
	h.mu.Unlock()
	defer h.active.Store(false)
	return h.server.Serve(h.listener)
}

// Shutdown は新規受付を止め、受理済み要求とACKを待ってからUDPを解放する。
func (h *HTTP3) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	h.closing = true
	h.active.Store(false)
	h.mu.Unlock()
	h.listener.StopAccepting()
	return errors.Join(h.server.Shutdown(ctx), h.listener.Close())
}

// Close は残存QUIC接続を中断し、自身が所有するUDP待受を解放する。
func (h *HTTP3) Close() error {
	h.mu.Lock()
	h.closing = true
	h.active.Store(false)
	h.mu.Unlock()
	return errors.Join(h.server.Close(), h.listener.Close())
}

// Shutdown はTCPとHTTP/3の新規受付を同時に止め、同じ期限で受理済み要求を待つ。
// HTTP/3の接続終了待ちの間にTCPだけ新規受付を続けないようにする。
func Shutdown(ctx context.Context, tcp *http.Server, h3 *HTTP3) error {
	if h3 == nil {
		return tcp.Shutdown(ctx)
	}
	done := make(chan error, 1)
	go func() { done <- h3.Shutdown(ctx) }()
	tcpErr := tcp.Shutdown(ctx)
	return errors.Join(tcpErr, <-done)
}
