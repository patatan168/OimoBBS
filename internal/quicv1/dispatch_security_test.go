// 既存CID宛てでも未対応versionや小さいInitialを復号queueへ入れないことを検査する。
package quicv1

import (
	"context"
	"encoding/binary"
	"net"
	"net/http/httptest"
	"testing"
)

func TestQUICDispatchRejectsInvalidEstablishedPackets(t *testing.T) {
	cert := httptest.NewTLSServer(nil)
	cfg := cert.TLS.Clone()
	cert.Close()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(socket, Config{TLSConfig: cfg, MaxConnections: 2})
	if err != nil {
		socket.Close()
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	peer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	c := &Conn{ctx: ctx, cancel: cancel, peer: peer, local: socket.LocalAddr().(*net.UDPAddr), incoming: make(chan receivedPacket, 4)}
	l.mu.Lock()
	l.connections["unknown0"] = c
	l.mu.Unlock()
	version := unvalidatedInitial(nil)
	binary.BigEndian.PutUint32(version[1:5], 0xface)
	initial := unvalidatedInitial(nil)
	h, err := parseHeader(initial)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{version, initial[:h.size]} {
		l.dispatch(data, nil, 0, peer)
		select {
		case <-c.incoming:
			t.Error("invalid packet reached established connection")
		default:
		}
	}
	l.dispatch(initial, nil, 0, peer)
	select {
	case <-c.incoming:
	default:
		t.Error("padded Initial was rejected")
	}
	// 併合datagramでは全体の長さでInitialを判定し、後続packetにも未検証入力の枠を適用する。
	calls := 0
	l.cfg.AllowUnvalidated = func(net.Addr) bool { calls++; return false }
	prefix, _ := makePacketHeader(spaceHandshake, []byte("unknown0"), []byte("client00"), 0, 1, false, 4)
	prefix = append(prefix, make([]byte, 17)...)
	second := unvalidatedInitial(nil)
	copy(second[6:14], "newCID00")
	l.dispatch(append(prefix, second[:1200-len(prefix)]...), nil, 0, peer)
	if calls != 1 || l.sendCalls.Load() != 0 {
		t.Fatal("coalesced Initial bypassed unvalidated gate", calls, l.sendCalls.Load())
	}
}
