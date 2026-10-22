// TLS前の接続元占有拒否・IPv6枠共有・並行解放を実TCPと固定接続で検査する。
package delivery

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestConnectionSourceCanonicalization(t *testing.T) {
	for _, tt := range []struct{ address, want string }{
		{"192.0.2.1:1234", "192.0.2.1/32"},
		{"[::ffff:192.0.2.1]:1234", "192.0.2.1/32"},
		{"[2001:db8:1::1]:1234", "2001:db8:1::/64"},
		{"[2001:db8:1::ffff]:4321", "2001:db8:1::/64"},
		{"[fe80::1%eth0]:1234", ""}, {"0.0.0.0:1234", ""}, {"[::]:1234", ""}, {"invalid", ""},
	} {
		t.Run(tt.address, func(t *testing.T) {
			got, err := connectionSource(connectionTestAddress(tt.address))
			if tt.want == "" {
				if err == nil {
					t.Fatal("invalid source accepted")
				}
			} else if err != nil || got.String() != tt.want {
				t.Fatal(got, err)
			}
		})
	}
	if _, err := connectionSource(nil); err == nil {
		t.Fatal("nil source accepted")
	}
}

type connectionTestAddress string

func (a connectionTestAddress) Network() string { return "tcp" }
func (a connectionTestAddress) String() string  { return string(a) }

type connectionTestConn struct {
	net.Conn
	address string
}

func (c connectionTestConn) RemoteAddr() net.Addr { return connectionTestAddress(c.address) }

func TestConnectionSourceQuotaAndConcurrentRelease(t *testing.T) {
	l := &boundedListener{limit: 3, perSource: 2, sources: map[netip.Prefix]int{}}
	var accepted []*boundedConn
	for _, address := range []string{"[2001:db8:1::1]:1", "[2001:db8:1::2]:2", "192.0.2.1:3"} {
		a, b := net.Pipe()
		defer b.Close()
		conn := connectionTestConn{Conn: a, address: address}
		release, ok := l.acquire(conn)
		if !ok {
			t.Fatal("valid source rejected", address)
		}
		accepted = append(accepted, &boundedConn{Conn: conn, release: release})
	}
	for _, address := range []string{"[2001:db8:1::3]:3", "192.0.2.2:4", "invalid"} {
		if _, ok := l.acquire(connectionTestConn{address: address}); ok {
			t.Fatal("overflow or invalid source accepted", address)
		}
	}
	// 一枠解放しても同じ/64が満杯なら拒否し、別/64には残りの全体枠を渡す。
	accepted[2].Close()
	if _, ok := l.acquire(connectionTestConn{address: "[2001:db8:1::3]:3"}); ok {
		t.Fatal("IPv6 rotation bypassed quota")
	}
	release, ok := l.acquire(connectionTestConn{address: "[2001:db8:2::1]:3"})
	if !ok {
		t.Fatal("other source rejected")
	}
	release()
	var done sync.WaitGroup
	for _, conn := range accepted {
		for range 8 {
			done.Go(func() { _ = conn.Close() })
		}
	}
	done.Wait()
	if l.total != 0 || len(l.sources) != 0 {
		t.Fatal("connection slots leaked", l.total, l.sources)
	}
}

func TestTCPSourceAdmissionBeforeHTTP(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := LimitListenerBySource(raw, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	first, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	accepted, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	result := make(chan net.Conn, 1)
	failure := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			failure <- err
			return
		}
		result <- conn
	}()
	// TLS/HTTPのバイトを一つも送らずに、同一接続元の二本目を拒否する。
	overflow, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer overflow.Close()
	_ = overflow.SetReadDeadline(time.Now().Add(3 * time.Second))
	var one [1]byte
	if _, err = overflow.Read(one[:]); err == nil {
		t.Fatal("source overflow not closed")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("source overflow waited", err)
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	other, err := dialer.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	select {
	case conn := <-result:
		_ = conn.Close()
	case err := <-failure:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("other source blocked by first source")
	}
}
