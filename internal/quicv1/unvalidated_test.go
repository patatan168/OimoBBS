// 未知接続の暗号処理・応答を入口で止め、稼働済み接続を巻き込まないことを検査する。
package quicv1

import (
	"context"
	"encoding/binary"
	"net"
	"net/http/httptest"
	"testing"
)

// unvalidatedInitial は復号不要のInitial headerと1200byte datagramを作る。
func unvalidatedInitial(token []byte) []byte {
	data := binary.BigEndian.AppendUint32([]byte{0xc0}, 1)
	data = append(data, 8)
	data = append(data, []byte("unknown0")...)
	data = append(data, 8)
	data = append(data, []byte("client00")...)
	data = appendVarint(data, uint64(len(token)))
	data = append(data, token...)
	data = appendVarint(data, 17)
	return append(data, make([]byte, 1200-len(data))...)
}

func TestUnvalidatedGatePrecedesRetryAndTokenWork(t *testing.T) {
	cert := httptest.NewTLSServer(nil)
	cfg := cert.TLS.Clone()
	cert.Close()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	allow, calls, admitted := false, 0, 0
	l, err := Listen(socket, Config{TLSConfig: cfg, MaxConnections: 2,
		AllowUnvalidated: func(net.Addr) bool { calls++; return allow },
		Admit:            func(context.Context, net.Addr) error { admitted++; return nil },
	})
	if err != nil {
		socket.Close()
		t.Fatal(err)
	}
	defer l.Close()
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	peer := sink.LocalAddr().(*net.UDPAddr)
	initial := unvalidatedInitial(nil)
	version := append([]byte(nil), initial...)
	binary.BigEndian.PutUint32(version[1:5], 0xface)
	for _, packet := range [][]byte{initial, unvalidatedInitial(make([]byte, 80)), version} {
		l.dispatch(packet, nil, 0, peer)
	}
	if calls != 3 || admitted != 0 || l.sendCalls.Load() != 0 || len(l.connections) != 0 {
		t.Fatalf("unvalidated input escaped gate: calls=%d admitted=%d sends=%d", calls, admitted, l.sendCalls.Load())
	}
	allow = true
	l.dispatch(initial, nil, 0, peer)
	l.dispatch(version, nil, 0, peer)
	if calls != 5 || l.sendCalls.Load() != 2 || len(l.connections) != 0 {
		t.Fatal("allowed Retry/version reply failed")
	}
	allow = false
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &Conn{ctx: ctx, cancel: cancel, peer: peer, local: socket.LocalAddr().(*net.UDPAddr), incoming: make(chan receivedPacket, 1)}
	l.mu.Lock()
	l.connections["knownCID"] = c
	l.mu.Unlock()
	packet := append([]byte{0x40}, []byte("knownCID")...)
	packet = append(packet, make([]byte, 1200)...)
	l.dispatch(packet, nil, 0, peer)
	select {
	case <-c.incoming:
	default:
		t.Fatal("existing connection blocked by unvalidated gate")
	}
	if calls != 5 {
		t.Fatal("existing packet consumed unvalidated quota")
	}
}
