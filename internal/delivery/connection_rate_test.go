// 接続の作り直し・IPv6の変更・索引上限と期限回復を、固定時刻で検査する。
package delivery

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sourceRateTestListener struct {
	net.Listener
	connections []net.Conn
}

func (l *sourceRateTestListener) Accept() (net.Conn, error) {
	if len(l.connections) == 0 {
		return nil, io.EOF
	}
	c := l.connections[0]
	l.connections = l.connections[1:]
	return c, nil
}

func TestConnectionRateSourceAndGlobal(t *testing.T) {
	now := time.Now()
	l := newConnectionRateGuard(ConnectionRate{GlobalRate: 4, GlobalBurst: 4, SourceRate: 1, SourceBurst: 2})
	a := netip.MustParsePrefix("192.0.2.1/32")
	b := netip.MustParsePrefix("192.0.2.2/32")
	for range 2 {
		if !l.allow(a, now) {
			t.Fatal("initial source burst rejected")
		}
	}
	for range 100 {
		if l.allow(a, now) {
			t.Fatal("reconnect bypassed source rate")
		}
	}
	for range 2 {
		if !l.allow(b, now) {
			t.Fatal("rejected source consumed global tokens")
		}
	}
	c := netip.MustParsePrefix("192.0.2.3/32")
	if l.allow(c, now) || len(l.sources) != 2 {
		t.Fatal("global overflow accepted or remembered")
	}
	if !l.allow(a, now.Add(time.Second)) || l.allow(a, now.Add(time.Second)) {
		t.Fatal("source refill is not one connection per second")
	}
	if l.allow(a, now) {
		t.Fatal("clock rollback refilled tokens")
	}
	if !l.allow(a, now.Add(2*time.Second)) {
		t.Fatal("source did not recover")
	}
}

func TestConnectionRateIndexBoundAndExpiry(t *testing.T) {
	now := time.Now()
	l := newConnectionRateGuard(ConnectionRate{GlobalRate: 10000, GlobalBurst: 10000, SourceRate: 1, SourceBurst: 2})
	for n := range connectionRateSources {
		ip := netip.AddrFrom4([4]byte{10, byte(n >> 8), byte(n), 1})
		if !l.allow(netip.PrefixFrom(ip, 32), now) {
			t.Fatal("source capacity rejected early", n)
		}
	}
	ip := netip.MustParsePrefix("192.0.2.1/32")
	if l.allow(ip, now) || len(l.sources) != connectionRateSources {
		t.Fatal("source index grew beyond its bound")
	}
	if !l.allow(ip, now.Add(time.Second)) || len(l.sources) != 1 {
		t.Fatal("fully refilled sources did not expire", len(l.sources))
	}
}

func TestConnectionRateInvalidPolicy(t *testing.T) {
	for _, p := range []ConnectionRate{{}, {1, 1, 0, 1}, {1, 1, 1, 0}, {1, 2, 2, 1}, {2, 1, 1, 2}, {-1, 2, 1, 1}} {
		if _, err := LimitConnectionRate(&sourceRateTestListener{}, p); err == nil {
			t.Fatal("invalid rate accepted", p)
		}
	}
	if _, err := LimitConnectionRate(nil, PublicConnectionRate()); err == nil {
		t.Fatal("nil listener accepted")
	}
}

func TestConnectionRateIPv6Rotation(t *testing.T) {
	raw := &sourceRateTestListener{}
	for _, address := range []string{"[2001:db8:1::1]:1", "[2001:db8:1::2]:2", "[::ffff:192.0.2.1]:3", "192.0.2.1:4", "invalid", "[2001:db8:2::1]:5"} {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		raw.connections = append(raw.connections, connectionTestConn{Conn: a, address: address})
	}
	l, err := LimitConnectionRate(raw, ConnectionRate{10, 10, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[2001:db8:1::1]:1", "[::ffff:192.0.2.1]:3", "[2001:db8:2::1]:5"} {
		conn, err := l.Accept()
		if err != nil || conn.RemoteAddr().String() != want {
			t.Fatal("source rotation or invalid peer bypassed quota", conn, err)
		}
		conn.Close()
	}
	if _, err := l.Accept(); err != io.EOF {
		t.Fatal("inner listener error not preserved", err)
	}
}

func TestConnectionRateConcurrentReservations(t *testing.T) {
	l := newConnectionRateGuard(ConnectionRate{256, 512, 16, 64})
	now := time.Now()
	source := netip.MustParsePrefix("192.0.2.1/32")
	var accepted atomic.Int64
	var done sync.WaitGroup
	for range 128 {
		done.Go(func() {
			if l.allow(source, now) {
				accepted.Add(1)
			}
		})
	}
	done.Wait()
	if accepted.Load() != 64 {
		t.Fatal("parallel reservations exceeded source burst", accepted.Load())
	}
}

func TestConnectionRateBeforeTLSAndKeepAlive(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP1", true: "HTTP2"}[h2], func(t *testing.T) {
			var handshakes atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
			server.EnableHTTP2 = h2
			server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				handshakes.Add(1)
				return nil, nil
			}}
			limited, err := LimitListenerBySource(server.Listener, 16, 8)
			if err != nil {
				t.Fatal(err)
			}
			server.Listener, err = LimitConnectionRate(limited, ConnectionRate{16, 16, 1, 2})
			if err != nil {
				t.Fatal(err)
			}
			server.StartTLS()
			defer server.Close()
			client := func(ip string) *http.Client {
				tr := server.Client().Transport.(*http.Transport).Clone()
				tr.DialContext = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}).DialContext
				tr.ForceAttemptHTTP2 = h2
				t.Cleanup(tr.CloseIdleConnections)
				return &http.Client{Transport: tr, Timeout: 2 * time.Second}
			}
			get := func(c *http.Client) {
				t.Helper()
				res, err := c.Get(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				if err != nil || res.StatusCode != 200 || string(body) != "ok" || (res.ProtoMajor == 2) != h2 {
					t.Fatal("ordinary request failed", res.Status, res.Proto, string(body), err)
				}
			}
			held := client("127.0.0.2")
			get(held)
			one := client("127.0.0.2")
			get(one)
			one.CloseIdleConnections()
			if res, err := client("127.0.0.2").Get(server.URL); err == nil {
				res.Body.Close()
				t.Fatal("reconnect overflow reached HTTP")
			}
			if handshakes.Load() != 2 {
				t.Fatal("rejected connection reached TLS", handshakes.Load())
			}
			get(held)
			if handshakes.Load() != 2 {
				t.Fatal("existing keep-alive was interrupted")
			}
			get(client("127.0.0.3"))
		})
	}
}
