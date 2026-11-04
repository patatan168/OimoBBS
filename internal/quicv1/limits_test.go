// 接続寿命が長い場合と不正入力の資源上限を検査する。
package quicv1

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestACKHistoryAndRingWindow(t *testing.T) {
	s := newNumberSpace()
	now := time.Now()
	for pn := uint64(0); pn < 20000; pn++ {
		if !s.receive(pn, now) || s.receive(pn, now) {
			t.Fatal("duplicate window", pn)
		}
	}
	if len(s.ranges) != 1 || s.ranges[0].low != 20000-4096 || s.ranges[0].high != 19999 {
		t.Fatal(s.ranges)
	}
	if s.receive(10, now) {
		t.Fatal("old packet accepted")
	}
	for pn := uint64(20001); pn < 20100; pn += 2 {
		s.receive(pn, now)
	}
	if len(s.ranges) > 16 {
		t.Fatal("ACK range budget")
	}
	s.ackPending = true
	r := wireReader{data: s.ackFrame(now)}
	_, _ = r.integer()
	largest, _ := r.integer()
	_, _ = r.integer()
	count, _ := r.integer()
	if largest != 20099 || count != 15 {
		t.Fatal(largest, count)
	}
}
func TestPeerCIDRotationBound(t *testing.T) {
	c := &Conn{peerCIDs: map[uint64]peerCID{0: {id: []byte("initial0")}}}
	for seq := uint64(1); seq < 10000; seq++ {
		data := appendVarint(nil, seq)
		data = appendVarint(data, seq)
		data = append(data, 8)
		data = append(data, make([]byte, 8)...)
		data[len(data)-1] = byte(seq)
		data = append(data, make([]byte, 16)...)
		r := wireReader{data: data}
		if err := c.newPeerCID(&r); err != nil {
			t.Fatal(seq, err)
		}
		if len(c.peerCIDs) != 1 || c.peerCIDSequence != seq || len(c.pending) != 1 {
			t.Fatal("CID state", seq)
		}
		c.pending = nil
		c.queuedBytes = 0
	}
}
func TestQueueBudgetCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &Conn{ctx: ctx, cancel: cancel}
	for range 10000 {
		c.queue(spaceApplication, make([]byte, 900))
	}
	if ctx.Err() == nil || c.queuedBytes > 512<<10 || len(c.pending) > 4096 {
		t.Fatal("unbounded queue")
	}
}
func TestRetryTokenBindsAddressAndCID(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	token, _ := cipher.NewGCM(block)
	l := &Listener{token: token}
	peer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	id := []byte("retryCID")
	original := []byte("originalCID")
	encoded := l.retryToken(peer, original, id)
	decoded, ok := l.verifyToken(peer, id, encoded)
	if !ok || string(decoded) != string(original) {
		t.Fatal("token roundtrip")
	}
	peer.Port++
	if _, ok = l.verifyToken(peer, id, encoded); ok {
		t.Fatal("address changed")
	}
	peer.Port--
	if _, ok = l.verifyToken(peer, []byte("otherCID"), encoded); ok {
		t.Fatal("CID changed")
	}
	encoded[len(encoded)-1] ^= 1
	if _, ok = l.verifyToken(peer, id, encoded); ok {
		t.Fatal("tampered token")
	}
}
func FuzzPacketHeader(f *testing.F) {
	f.Add([]byte{0x43, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(make([]byte, 1200))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := parseHeader(data)
		if err == nil && (h.size > len(data) || h.pnOffset > h.size) {
			t.Fatal("header bound")
		}
	})
}
func FuzzReassembly(f *testing.F) {
	f.Add(uint64(0), []byte("body"), true)
	f.Fuzz(func(t *testing.T, offset uint64, data []byte, fin bool) {
		r := reassembly{limit: 4096}
		_, _ = r.insert(offset, data, fin)
		if r.buffered > 4096 {
			t.Fatal("buffer bound")
		}
	})
}

// 同じ書込blockの後続payloadを、frame連結やpaddingで上書きさせない。
func TestFrameDataHasPrivateAppendCapacity(t *testing.T) {
	data := make([]byte, 2*(sendChunk+frameHeadroom))
	for i := range data {
		data[i] = byte(i)
	}
	r := &writeRequest{data: data, size: 2 * sendChunk}
	secondBefore := append([]byte(nil), data[sendChunk+frameHeadroom:]...)
	first := r.frameData(0, 0, sendChunk, false)
	_ = append(first, make([]byte, 200)...)
	for i, b := range secondBefore {
		if data[sendChunk+frameHeadroom+i] != b {
			t.Fatal("following payload modified")
		}
	}
}

func TestWriteDeadlineWhileCommandQueueBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &Conn{ctx: ctx, commands: make(chan any)}
	s := newStream(c, 0)
	_ = s.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
	n, err := s.Write([]byte("body"))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(n, err)
	}
	_ = s.SetWriteDeadline(time.Now().Add(-time.Second))
	n, err = s.Write([]byte("expired"))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(n, err)
	}
}

// 同じCID・接続元でも宛先IPが変わったpacketを既存接続へ渡さない。
func TestDestinationAddressIsBoundToConnection(t *testing.T) {
	cert := httptest.NewTLSServer(nil)
	cfg := cert.TLS.Clone()
	cert.Close()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(socket, Config{TLSConfig: cfg, MaxConnections: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	port := socket.LocalAddr().(*net.UDPAddr).Port
	c := &Conn{ctx: ctx, cancel: cancel, id: []byte("routeCID"), peer: client.LocalAddr().(*net.UDPAddr), local: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, incoming: make(chan receivedPacket, 2)}
	listener.mu.Lock()
	listener.connections[string(c.id)] = c
	listener.mu.Unlock()
	packet := append([]byte{0x40}, c.id...)
	packet = append(packet, make([]byte, 20)...)
	_, _ = client.WriteToUDP(packet, c.local)
	select {
	case <-c.incoming:
	case <-time.After(time.Second):
		t.Fatal("original destination not routed")
	}
	_, _ = client.WriteToUDP(packet, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: port})
	select {
	case <-c.incoming:
		t.Fatal("changed destination accepted")
	case <-time.After(30 * time.Millisecond):
	}
}

// UDP受信自体が停止した場合、新規受付を継続してHTTP/3を広告し続けない。
func TestListenerReadFailureStopsAcceptance(t *testing.T) {
	cert := httptest.NewTLSServer(nil)
	cfg := cert.TLS.Clone()
	cert.Close()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(socket, Config{TLSConfig: cfg, MaxConnections: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = socket.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = listener.Accept(ctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dead UDP listener kept accepting: %v", err)
	}
}
