// 鍵更新・ACK反復・受信領域の寿命を検査し、通常経路と拒否経路のコストを測る。
package quicv1

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// keyTestConn はネットワークへ送信せず、実AEADで鍵更新を検査する接続を作る。
func keyTestConn(t *testing.T) (*Conn, *packetKeys) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	c := &Conn{ctx: ctx, cancel: cancel, listener: &Listener{cfg: Config{KeyUpdateAfter: 32}, sendQueue: make(chan sendBurst, 32), closed: make(chan struct{})},
		id: []byte("server00"), peerID: []byte("client00"), handshakeDone: true, recovery: newRecovery(), mtu: 1200}
	for i := range c.spaces {
		c.spaces[i] = newNumberSpace()
	}
	read, write, err := initialKeys([]byte("key-test"))
	if err != nil {
		t.Fatal(err)
	}
	c.spaces[spaceApplication].read, c.spaces[spaceApplication].write = read, write
	t.Cleanup(func() {
		cancel()
		c.releaseBuffers()
		for len(c.listener.sendQueue) > 0 {
			for _, p := range (<-c.listener.sendQueue).packets {
				releasePacket(p)
			}
		}
	})
	return c, read
}

// protectedPing は鍵phaseとpacket番号を認証した実packetを作る。
func protectedPing(t *testing.T, key *packetKeys, pn uint64, phase bool) receivedPacket {
	t.Helper()
	header, offset := makePacketHeader(spaceApplication, []byte("server00"), nil, pn, 2, phase, 2)
	data, err := key.sealPacket(header, []byte{1, 0}, pn, offset)
	if err != nil {
		t.Fatal(err)
	}
	return receivedPacket{data: data, header: packetHeader{space: spaceApplication, pnOffset: offset}, at: time.Now()}
}

func TestKeyUpdateRequiresACKOfCurrentPhase(t *testing.T) {
	for _, sendACK := range []bool{false, true} {
		t.Run(map[bool]string{false: "premature", true: "acknowledged"}[sendACK], func(t *testing.T) {
			c, initial := keyTestConn(t)
			next, _ := initial.next()
			if err := c.receivePacket(protectedPing(t, next, 1, true)); err != nil {
				t.Fatal(err)
			}
			if sendACK {
				if err := c.flush(time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			after, _ := next.next()
			err := c.receivePacket(protectedPing(t, after, 2, false))
			if sendACK {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var transport *transportError
			if !errors.As(err, &transport) || transport.code != 0xe {
				t.Fatal("unacknowledged key update accepted", err)
			}
		})
	}
}

func TestOldKeyRetentionIgnoresPTOBackoff(t *testing.T) {
	c, initial := keyTestConn(t)
	c.recovery.ptoCount = 6
	next, _ := initial.next()
	if err := c.receivePacket(protectedPing(t, next, 1, true)); err != nil {
		t.Fatal(err)
	}
	if c.previousReadUntil.After(time.Now().Add(4 * c.recovery.basePTO())) {
		t.Fatal("PTO backoff extended old key retention")
	}
}

func TestKeyUpdateResponseToLocalUpdateIsAllowed(t *testing.T) {
	c, initial := keyTestConn(t)
	next, _ := initial.next()
	if err := c.receivePacket(protectedPing(t, next, 1, true)); err != nil {
		t.Fatal(err)
	}
	// 自分が先に送信鍵を更新した場合、peerの次phaseは応答であり追加の更新要求ではない。
	c.keyPhase = false
	c.spaces[spaceApplication].write, _ = c.spaces[spaceApplication].write.next()
	after, _ := next.next()
	if err := c.receivePacket(protectedPing(t, after, 2, false)); err != nil {
		t.Fatal(err)
	}
}

func TestOldReadKeysAreDiscarded(t *testing.T) {
	c, initial := keyTestConn(t)
	c.previousRead, c.previousReadUntil = initial, time.Now().Add(-time.Second)
	c.onTimer(time.Now())
	if c.previousRead != nil {
		t.Fatal("expired packet key retained")
	}
}

func TestACKProcessingIsBoundedPerPacket(t *testing.T) {
	for space := range 3 {
		for _, kind := range []byte{2, 3} {
			for _, count := range []int{8, 9} {
				c := &Conn{recovery: newRecovery()}
				c.spaces[space] = newNumberSpace()
				c.spaces[space].next = 1
				ack := []byte{kind, 0, 0, 0, 0}
				if kind == 3 {
					ack = append(ack, 0, 0, 0)
				}
				_, err := c.frames(space, bytes.Repeat(ack, count), time.Now())
				if (err == nil) != (count == 8) {
					t.Fatal("incorrect ACK budget", space, kind, count, err)
				}
			}
		}
	}
}

func TestAuthenticatedACKFloodIsRejected(t *testing.T) {
	c, key := keyTestConn(t)
	c.spaces[spaceApplication].next = 1
	body := bytes.Repeat([]byte{2, 0, 0, 0, 0}, 9)
	header, offset := makePacketHeader(spaceApplication, c.id, nil, 1, len(body), false, 2)
	data, err := key.sealPacket(header, body, 1, offset)
	if err != nil {
		t.Fatal(err)
	}
	err = c.receivePacket(receivedPacket{data: data, header: packetHeader{space: spaceApplication, pnOffset: offset}, at: time.Now()})
	var transport *transportError
	if !errors.As(err, &transport) || transport.code != 1 || !c.spaces[spaceApplication].received {
		t.Fatal("authenticated ACK flood accepted", err)
	}
}

func TestReassemblyReleasesConsumedReferences(t *testing.T) {
	r := reassembly{limit: 4096}
	if _, err := r.insert(0, []byte("retained"), false); err != nil {
		t.Fatal(err)
	}
	slots := r.parts[:cap(r.parts)]
	_ = r.pop()
	if slots[0].data != nil {
		t.Fatal("consumed payload retained by reassembly slots")
	}
}

// destinationFixture はOSが返した宛先制御情報を採取し、使い捨てsocketだけを保持する。
func destinationFixture(tb testing.TB) (*Listener, []byte) {
	tb.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = socket.Close() })
	if err = ipv4.NewPacketConn(socket).SetControlMessage(ipv4.FlagDst, true); err != nil {
		tb.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: socket.LocalAddr().(*net.UDPAddr).Port})
	if err != nil {
		tb.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Write([]byte{1}); err != nil {
		tb.Fatal(err)
	}
	_ = socket.SetReadDeadline(time.Now().Add(time.Second))
	var data [8]byte
	control := make([]byte, 256)
	_, n, _, _, err := socket.ReadMsgUDP(data[:], control)
	if err != nil {
		tb.Fatal(err)
	}
	return &Listener{socket: socket}, control[:n]
}

func TestDestinationCacheOwnsKernelControl(t *testing.T) {
	l, control := destinationFixture(t)
	first := l.destination(control)
	if first == nil || !first.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatal(first)
	}
	if l.destination(control) != first {
		t.Error("unchanged destination was reallocated")
	}
	copyOfControl := bytes.Clone(control)
	clear(control)
	if !first.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatal("kernel buffer overwrote retained destination")
	}
	if l.destination(copyOfControl) != first {
		t.Fatal("cache retained caller-owned control bytes")
	}
	if l.destination(nil) != nil {
		t.Fatal("wildcard destination guessed without control data")
	}
}

func BenchmarkPacketDestination(b *testing.B) {
	l, control := destinationFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if l.destination(control) == nil {
			b.Fatal("missing destination")
		}
	}
}

func BenchmarkReassemblyOrdered(b *testing.B) {
	data := bytes.Repeat([]byte{1}, 1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		r := reassembly{limit: 64 << 10}
		if _, err := r.insert(0, data, true); err != nil {
			b.Fatal(err)
		}
		if len(r.pop()) != len(data) {
			b.Fatal("reassembly stalled")
		}
	}
}

func BenchmarkACKFrameFlood(b *testing.B) {
	c := &Conn{recovery: newRecovery()}
	c.spaces[spaceApplication] = newNumberSpace()
	c.spaces[spaceApplication].next = 1
	data := bytes.Repeat([]byte{2, 0, 0, 0, 0}, 64)
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = c.frames(spaceApplication, data, now)
	}
}

func BenchmarkReassemblyFragments(b *testing.B) {
	data := bytes.Repeat([]byte{1}, 1024)
	b.ReportAllocs()
	b.SetBytes(16 * int64(len(data)))
	for b.Loop() {
		r := reassembly{limit: 64 << 10}
		for i := range 16 {
			if _, err := r.insert(uint64(i*len(data)), data, i == 15); err != nil {
				b.Fatal(err)
			}
			if len(r.pop()) != len(data) {
				b.Fatal("reassembly stalled")
			}
		}
	}
}

// FuzzDestinationControl はkernel制御情報の解析とcacheを、有界の不正入力で検査する。
func FuzzDestinationControl(f *testing.F) {
	l, control := destinationFixture(f)
	f.Add(control)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256 {
			return
		}
		owned := bytes.Clone(data)
		address := l.destination(owned)
		if address == nil {
			return
		}
		before := bytes.Clone(address.IP)
		clear(owned)
		if address.IP.IsUnspecified() || !bytes.Equal(address.IP, before) {
			t.Fatal("destination owns mutable kernel storage")
		}
	})
}

// FuzzKeyUpdateSequence はpacket受信・ACK送信・期限到来を交互に入力し、鍵状態の境界を検査する。
func FuzzKeyUpdateSequence(f *testing.F) {
	f.Add([]byte{1, 1})
	f.Add([]byte{1, 2, 1})
	f.Add([]byte{0, 1, 3, 2, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		c, key := keyTestConn(t)
		phase := false
		pn := uint64(1)
		for i, action := range data {
			if i >= 16 {
				break
			}
			switch action % 4 {
			case 2:
				if err := c.flush(time.Now()); err != nil {
					return
				}
			case 3:
				c.onTimer(time.Now().Add(4 * c.recovery.basePTO()))
			default:
				if action%4 == 1 {
					key, _ = key.next()
					phase = !phase
				}
				if err := c.receivePacket(protectedPing(t, key, pn, phase)); err != nil {
					return
				}
				pn++
			}
			if c.queuedBytes > 512<<10 || len(c.pending) > 4096 {
				t.Fatal("key update exceeded queue budget")
			}
		}
	})
}
