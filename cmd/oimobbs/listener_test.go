// 起動経路のTLS前接続枠と認証edgeの集約接続維持を固定listenerで検査する。
package main

import (
	"io"
	"net"
	"oimobbs/internal/bootstrap"
	"testing"
)

type sourceTestConn struct {
	net.Conn
	ip     string
	closed bool
}

func (c *sourceTestConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(c.ip), Port: 1234}
}
func (c *sourceTestConn) Close() error { c.closed = true; return nil }

type sourceTestListener struct {
	net.Listener
	connections []*sourceTestConn
}

func (l *sourceTestListener) Accept() (net.Conn, error) {
	if len(l.connections) == 0 {
		return nil, io.EOF
	}
	conn := l.connections[0]
	l.connections = l.connections[1:]
	return conn, nil
}

func TestPublicListenerSourceLimits(t *testing.T) {
	for _, edge := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "edge"}[edge], func(t *testing.T) {
			cfg := bootstrap.Config{}
			if edge {
				cfg.Edge = &bootstrap.EdgeConfig{}
				cfg.TrustedProxies = []string{"192.0.2.1/32"}
			}
			raw := &sourceTestListener{}
			for range 65 {
				raw.connections = append(raw.connections, &sourceTestConn{ip: "192.0.2.1"})
			}
			overflow := raw.connections[64]
			other := &sourceTestConn{ip: "192.0.2.2"}
			raw.connections = append(raw.connections, other)
			listener, err := limitPublicListener(raw, cfg)
			if err != nil {
				t.Fatal(err)
			}
			var accepted []net.Conn
			defer func() {
				for _, c := range accepted {
					_ = c.Close()
				}
			}()
			for range 64 {
				c, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				accepted = append(accepted, c)
			}
			c, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			accepted = append(accepted, c)
			if edge {
				if overflow.closed || c.RemoteAddr().String() != overflow.RemoteAddr().String() {
					t.Fatal("edge aggregation limited as one user")
				}
			} else if !overflow.closed || c.RemoteAddr().String() != other.RemoteAddr().String() {
				t.Fatal("direct source occupied additional connection slots")
			}
		})
	}
}

func TestEdgeListenerRejectsUntrustedPeerBeforeTLS(t *testing.T) {
	blocked := &sourceTestConn{ip: "192.0.2.2"}
	allowed := &sourceTestConn{ip: "192.0.2.1"}
	raw := &sourceTestListener{connections: []*sourceTestConn{blocked, allowed}}
	cfg := bootstrap.Config{Edge: &bootstrap.EdgeConfig{}, TrustedProxies: []string{"192.0.2.1/32"}}
	listener, err := limitPublicListener(raw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !blocked.closed || allowed.closed || conn.RemoteAddr().String() != allowed.RemoteAddr().String() {
		t.Fatal("untrusted edge peer reached TLS admission")
	}
	for _, prefixes := range [][]string{nil, {"0.0.0.0/0"}, {"192.0.2.1/24"}, {"invalid"}} {
		cfg.TrustedProxies = prefixes
		if _, err := limitPublicListener(raw, cfg); err == nil {
			t.Fatal("invalid edge source policy accepted", prefixes)
		}
	}
}
