// 満杯TCP接続の即時closeと、二重close後の枠回復を実listenerで検査する。
package delivery

import (
	"net"
	"testing"
	"time"
)

func TestTCPConnectionAdmissionAndRelease(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	listener, e := LimitListener(raw, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	first, e := net.Dial("tcp", raw.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	accepted, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer accepted.Close()
	next := make(chan net.Conn, 1)
	failure := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			failure <- e
			return
		}
		next <- conn
	}()
	overflow, e := net.Dial("tcp", raw.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer overflow.Close()
	_ = overflow.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, e = overflow.Read(one[:]); e == nil {
		t.Fatal("full connection not closed")
	} else if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		t.Fatal("full connection waited", e)
	}
	_ = accepted.Close()
	_ = accepted.Close()
	recovered, e := net.Dial("tcp", raw.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer recovered.Close()
	select {
	case conn := <-next:
		_ = conn.Close()
	case e := <-failure:
		t.Fatal(e)
	case <-time.After(time.Second):
		t.Fatal("connection slot leaked")
	}
}
