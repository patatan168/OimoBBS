// Package httptransport は独自QUIC/HTTP/3とTCPを併設し、UDP障害時もHTTP/2を継続する。
package httptransport

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"

	"oimobbs/internal/delivery"
	"oimobbs/internal/http3native"
	"oimobbs/internal/quicv1"
)

// HTTP3 はTCPと同じhandlerを独自QUIC上で提供し、UDP待受の寿命と広告状態を管理する。
type HTTP3 struct {
	server   *http3native.Server
	listener *quicv1.Listener
	active   atomic.Bool
	started  atomic.Bool
	mu       sync.Mutex
	closing  bool
}

// Prepare は外部UDPを許可した場合だけTCPと同じ実portへUDPを確保する。
// OSでUDPを使えなければ理由を返してHTTP/2を継続し、ルーターの到達性は推定しない。
// TCP開始前に呼び、返した所有者のServe/Shutdown/Closeを呼出元で管理する。
func Prepare(tcp *http.Server, address net.Addr, origin string, enabled bool, total, perSource int) (*HTTP3, string, error) {
	if !enabled {
		return nil, "外部UDPの到達性が未設定", nil
	}
	if tcp.TLSConfig == nil {
		return nil, "TLS待受なし", nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, "", errors.New("HTTP/3 requires HTTPS origin")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
	}
	if err != nil || port < 1 || port > 65535 {
		return nil, "", errors.New("invalid HTTP/3 public port")
	}
	guard, err := delivery.NewQUICAdmission(total, perSource)
	if err != nil {
		return nil, "", err
	}
	addr, err := net.ResolveUDPAddr("udp", address.String())
	if err != nil {
		return nil, "", err
	}
	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Sprintf("OSのUDP待受を使用できません: %v", err), nil
	}
	cfg := tcp.TLSConfig.Clone()
	cfg.NextProtos = []string{"h3"}
	listener, err := quicv1.Listen(socket, quicv1.Config{TLSConfig: cfg, MaxConnections: total, Admit: guard.Admit, AllowUnvalidated: guard.AllowUnvalidated})
	if err != nil {
		socket.Close()
		return nil, fmt.Sprintf("OSのQUIC待受を使用できません: %v", err), nil
	}
	original := tcp.Handler
	if original == nil {
		original = http.DefaultServeMux
	}
	nativeHTTP := http.Server{Handler: original, ConnContext: tcp.ConnContext, ReadHeaderTimeout: tcp.ReadHeaderTimeout, ReadTimeout: tcp.ReadTimeout, WriteTimeout: tcp.WriteTimeout, IdleTimeout: tcp.IdleTimeout, MaxHeaderBytes: tcp.MaxHeaderBytes}
	h := &HTTP3{server: &http3native.Server{HTTP: &nativeHTTP}, listener: listener}
	tcp.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.ProtoMajor < 3 {
			if h.active.Load() {
				w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=60`, port))
			} else if h.started.Load() {
				w.Header().Set("Alt-Svc", "clear")
			}
		}
		original.ServeHTTP(w, r)
	})
	return h, "UDP待受の確保に成功（独自QUIC/HTTP3）", nil
}

// NativeStats はアドレスや要求内容を含まない、読取り専用の集計値を返す。
func (h *HTTP3) NativeStats() *quicv1.Stats {
	if h == nil || h.listener == nil {
		return nil
	}
	s := h.listener.Stats()
	return &s
}
