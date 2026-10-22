// HTTP要求とTCP接続を有界にし、処理終了または接続close時に枠を返す。
package delivery

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
)

// RequestGate は全体とcanonical IP別の同時要求を管理する。待機queueは持たない。
type RequestGate struct {
	mu                   sync.Mutex
	closed               bool
	total, global, perIP int
	ips                  map[netip.Addr]int
}

// Close は新規要求の受付だけを止める。受理済みの要求とその枠解放は通常どおり完了する。
// 同じgateは再開せず、新しいサーバーには新しいgateを使用する。
func (g *RequestGate) Close() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}

// NewRequestGate はglobal/perIPが正の要求枠を作る。
func NewRequestGate(global, perIP int) (*RequestGate, error) {
	if global < 1 || perIP < 1 || perIP > global {
		return nil, errors.New("invalid request admission limits")
	}
	return &RequestGate{global: global, perIP: perIP, ips: map[netip.Addr]int{}}, nil
}

// Wrap はアプリ受理ヘッダ16KiBと要求枠を検査する。503/431も外側の送信枠へ通す。
func (g *RequestGate) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size := len("Host: ") + len(r.Host) + 2
		for k, values := range r.Header {
			for _, v := range values {
				size += len(k) + len(v) + 4
			}
		}
		if size > 16<<10 {
			http.Error(w, "要求ヘッダが大きすぎます。", 431)
			return
		}
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		ip, err := netip.ParseAddr(host)
		if e != nil || err != nil || ip.Zone() != "" {
			http.Error(w, "接続元を確認できません。", 400)
			return
		}
		ip = ip.Unmap()
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			w.Header().Set("Retry-After", "1")
			http.Error(w, "停止処理中です。", 503)
			return
		}
		if g.total >= g.global || g.ips[ip] >= g.perIP {
			g.mu.Unlock()
			w.Header().Set("Retry-After", "1")
			http.Error(w, "現在混雑しています。", 503)
			return
		}
		g.total++
		g.ips[ip]++
		g.mu.Unlock()
		defer func() {
			g.mu.Lock()
			g.total--
			g.ips[ip]--
			if g.ips[ip] == 0 {
				delete(g.ips, ip)
			}
			g.mu.Unlock()
		}()
		next.ServeHTTP(w, r)
	})
}

type boundedListener struct {
	net.Listener
	mu           sync.Mutex
	total, limit int
	perSource    int
	sources      map[netip.Prefix]int
}
type boundedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

// LimitListener はTCP接続超過をaccept直後にcloseする。管理/公開の枠は独立する。
func LimitListener(inner net.Listener, limit int) (net.Listener, error) {
	if inner == nil || limit < 1 {
		return nil, errors.New("invalid connection admission limit")
	}
	return &boundedListener{Listener: inner, limit: limit}, nil
}

// LimitListenerBySource はTLS・HTTPの読出し前に全体と接続元別のTCP枠を確保する。
// IPv4はIPごと、IPv6は/64ごとに数え、同一ネットワーク内のアドレス変更でも枠を共有する。
// 認証edgeの集約接続には使わず、利用者別の要求枠を別途適用する。
func LimitListenerBySource(inner net.Listener, limit, perSource int) (net.Listener, error) {
	if inner == nil || limit < 1 || perSource < 1 || perSource > limit {
		return nil, errors.New("invalid source connection admission limits")
	}
	return &boundedListener{Listener: inner, limit: limit, perSource: perSource, sources: map[netip.Prefix]int{}}, nil
}

// connectionSource は実socketの接続元だけを数え、申告ヘッダを参照しない。
func connectionSource(address net.Addr) (netip.Prefix, error) {
	if address == nil {
		return netip.Prefix{}, errors.New("missing connection source")
	}
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil || endpoint.Addr().Zone() != "" || endpoint.Addr().IsUnspecified() {
		return netip.Prefix{}, errors.New("invalid connection source")
	}
	ip := endpoint.Addr().Unmap()
	bits := 32
	if ip.Is6() {
		bits = 64
	}
	return netip.PrefixFrom(ip, bits).Masked(), nil
}

// acquire は枠を予約し、boundedConnのonceから呼ぶ解放関数を返す。拒否した接続の索引は保持しない。
func (l *boundedListener) acquire(conn net.Conn) (func(), bool) {
	var source netip.Prefix
	if l.perSource > 0 {
		var err error
		source, err = connectionSource(conn.RemoteAddr())
		if err != nil {
			return nil, false
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.limit || l.perSource > 0 && l.sources[source] >= l.perSource {
		return nil, false
	}
	l.total++
	if l.perSource > 0 {
		l.sources[source]++
	}
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.total--
		if l.perSource > 0 {
			l.sources[source]--
			if l.sources[source] == 0 {
				delete(l.sources, source)
			}
		}
	}, true
}

// Accept は稼働枠のある接続だけを返し、満杯の接続を待機させない。
func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		if release, ok := l.acquire(conn); ok {
			return &boundedConn{Conn: conn, release: release}, nil
		}
		_ = conn.Close()
	}
}

// Close は下位closeが失敗しても同じ接続の枠を二重に戻さない。
func (c *boundedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
