// 暗号化後の送信失敗と再送制御を検査し、番号・経路応答・鍵期限の境界を守る。
package quicv1

import (
	"bytes"
	"crypto/cipher"
	"net"
	"testing"
	"time"
)

type nonceAuditAEAD struct {
	cipher.AEAD
	used     map[string]bool
	repeated bool
}

// Seal は実際の暗号処理を保ち、同じ鍵でnonceを再利用したかだけを記録する。
func (a *nonceAuditAEAD) Seal(dst, nonce, plaintext, additional []byte) []byte {
	key := string(nonce)
	a.repeated = a.repeated || a.used[key]
	a.used[key] = true
	return a.AEAD.Seal(dst, nonce, plaintext, additional)
}

func TestFailedSenderDoesNotReusePacketNumber(t *testing.T) {
	c, _ := keyTestConn(t)
	key := c.spaces[spaceApplication].write
	audit := &nonceAuditAEAD{AEAD: key.aead, used: make(map[string]bool)}
	key.aead = audit
	close(c.listener.closed)
	c.listener.sendQueue = make(chan sendBurst)
	if err := c.transmit(spaceApplication, []byte{1}, nil, time.Now(), true); err != net.ErrClosed {
		t.Fatal(err)
	}
	// senderだけを差し替え、同じ接続状態で継続した場合の番号再利用も防ぐ。
	c.listener.closed = make(chan struct{})
	c.listener.sendQueue = make(chan sendBurst, 32)
	if err := c.transmit(spaceApplication, []byte{1, 1}, nil, time.Now(), true); err != nil {
		t.Fatal(err)
	}
	if audit.repeated || c.spaces[spaceApplication].next != 2 {
		t.Fatal("packet nonce reused after sender failure", audit.repeated, c.spaces[spaceApplication].next)
	}
}

func TestMTUProbeRespectsHistoryBeforeEncryption(t *testing.T) {
	c, _ := keyTestConn(t)
	s := &c.spaces[spaceApplication]
	for i := range uint64(1024) {
		s.sent[i] = sentPacket{}
	}
	s.next = 1024
	c.recovery.cwnd = 1 << 20
	c.peerMaxUDP = 1452
	c.mtuProbeAt = time.Now().Add(-time.Second)
	c.maybeProbeMTU(time.Now())
	if len(c.listener.sendQueue) != 0 || c.listener.sentPackets.Load() != 0 || s.next != 1024 {
		t.Fatal("MTU probe encrypted or queued beyond history limit", len(c.listener.sendQueue), s.next)
	}
}

func TestHistoryOverflowDoesNotReuseNonceForACK(t *testing.T) {
	c, _ := keyTestConn(t)
	s := &c.spaces[spaceApplication]
	audit := &nonceAuditAEAD{AEAD: s.write.aead, used: make(map[string]bool)}
	s.write.aead = audit
	for i := range uint64(1024) {
		s.sent[i] = sentPacket{}
	}
	s.next = 1024
	c.recovery.cwnd = 1 << 20
	c.peerMaxUDP = 1452
	c.mtuProbeAt = time.Now().Add(-time.Second)
	c.maybeProbeMTU(time.Now())
	if err := c.transmit(spaceApplication, []byte{2, 0, 0, 0, 0}, nil, time.Now(), true); err != nil {
		t.Fatal(err)
	}
	if audit.repeated || len(c.listener.sendQueue) != 1 || s.next != 1025 {
		t.Fatal("probe failure reused nonce for ACK", audit.repeated, len(c.listener.sendQueue), s.next)
	}
}

func TestPacketNumberExhaustionStopsEncryption(t *testing.T) {
	c, _ := keyTestConn(t)
	c.spaces[spaceApplication].next = maxVarint
	if err := c.transmit(spaceApplication, []byte{1}, nil, time.Now(), true); err == nil || len(c.listener.sendQueue) != 0 {
		t.Fatal("exhausted packet number sent", err)
	}
}

func TestExhaustionStopsAllPacketSpaces(t *testing.T) {
	c, _ := keyTestConn(t)
	key := c.spaces[spaceApplication].write
	audit := &nonceAuditAEAD{AEAD: key.aead, used: make(map[string]bool)}
	key.aead = audit
	c.spaces[spaceHandshake].write = key
	c.spaces[spaceApplication].next = maxVarint
	_ = c.transmit(spaceApplication, []byte{1}, nil, time.Now(), true)
	err := c.transmit(spaceHandshake, []byte{1}, nil, time.Now(), true)
	if err == nil || len(audit.used) != 0 || len(c.listener.sendQueue) != 0 {
		t.Fatal("cancelled connection encrypted in another packet space", err, len(audit.used))
	}
}

func TestPathResponseIsPaddedAndNotRetransmitted(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run(map[bool]string{false: "pto", true: "loss"}[loss], func(t *testing.T) {
			c, _ := keyTestConn(t)
			challenge := append([]byte{0x1a}, []byte("probe123")...)
			now := time.Now()
			if _, err := c.frames(spaceApplication, challenge, now); err != nil {
				t.Fatal(err)
			}
			if err := c.flush(now); err != nil {
				t.Fatal(err)
			}
			burst := <-c.listener.sendQueue
			defer func() {
				for _, p := range burst.packets {
					releasePacket(p)
				}
			}()
			if len(burst.packets) != 1 {
				t.Fatal("unexpected response packet count", len(burst.packets))
			}
			if len(burst.packets[0].data) < 1200 {
				t.Error("path response did not validate minimum datagram size", len(burst.packets[0].data))
			}
			if c.recovery.inFlight < 1200 {
				t.Error("path response bypassed congestion accounting", c.recovery.inFlight)
			}
			if loss {
				c.spaces[spaceApplication].hasAcked = true
				c.spaces[spaceApplication].largestAcked = 3
				c.detectLost(spaceApplication, now.Add(time.Second))
				if len(c.pending) != 0 || c.recovery.inFlight != 0 {
					t.Fatal("lost path response was requeued", len(c.pending), c.recovery.inFlight)
				}
				return
			}
			c.onTimer(now.Add(2 * c.recovery.basePTO()))
			probe := <-c.listener.sendQueue
			defer func() {
				for _, p := range probe.packets {
					releasePacket(p)
				}
			}()
			payload, _, _, err := c.spaces[spaceApplication].write.openPacket(probe.packets[0].data, 1+len(c.peerID), 1)
			if err != nil || bytes.Contains(payload, []byte("probe123")) || len(payload) == 0 || payload[0] != 1 {
				t.Fatal("PTO retransmitted PATH_RESPONSE", payload, err)
			}
		})
	}
}

func TestOldKeyExpirySchedulesWake(t *testing.T) {
	c, key := keyTestConn(t)
	now := time.Now()
	c.lastActivity, c.idleTimeout = now, 30*time.Second
	c.previousRead, c.previousReadUntil = key, now.Add(20*time.Millisecond)
	if delay := c.nextWake(now); delay > 20*time.Millisecond {
		t.Fatal("old key expiry omitted from timer", delay)
	}
}

func TestPathResponseFloodIsBounded(t *testing.T) {
	c, _ := keyTestConn(t)
	challenge := append([]byte{0x1a}, []byte("floodPTH")...)
	if _, err := c.frames(spaceApplication, bytes.Repeat(challenge, 9), time.Now()); err == nil {
		t.Fatal("path response flood accepted")
	}
}

func TestPathResponseCreditRefillsWithinBound(t *testing.T) {
	c, _ := keyTestConn(t)
	now := time.Unix(1, 0)
	for range 8 {
		if !c.allowPathResponse(now) {
			t.Fatal("initial response credit lost")
		}
	}
	if c.allowPathResponse(now) || c.allowPathResponse(now.Add(999*time.Millisecond)) {
		t.Fatal("response credit refilled early")
	}
	if !c.allowPathResponse(now.Add(time.Second)) || c.allowPathResponse(now.Add(time.Second)) {
		t.Fatal("incorrect response refill")
	}
	for range 8 {
		if !c.allowPathResponse(now.Add(time.Hour)) {
			t.Fatal("response credit did not refill")
		}
	}
	if c.allowPathResponse(now.Add(time.Hour)) {
		t.Fatal("idle time accumulated unbounded credit")
	}
}

func TestPathResponsePaddingAcrossCIDAndPacketNumbers(t *testing.T) {
	for _, size := range []int{0, 8, 20} {
		for _, pn := range []uint64{0, 1 << 16} {
			c, _ := keyTestConn(t)
			c.peerID = bytes.Repeat([]byte{1}, size)
			c.spaces[spaceApplication].next = pn
			if _, err := c.frames(spaceApplication, append([]byte{0x1a}, []byte("sizeTest")...), time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := c.flush(time.Now()); err != nil {
				t.Fatal(err)
			}
			burst := <-c.listener.sendQueue
			for _, packet := range burst.packets {
				length := len(packet.data)
				releasePacket(packet)
				if length != 1200 {
					t.Fatal("wrong minimum datagram size", size, pn, length)
				}
			}
		}
	}
}

// FuzzSendStateSequence は送信・PTO・損失・sender失敗を重ね、nonceと所有権を検査する。
func FuzzSendStateSequence(f *testing.F) {
	f.Add([]byte{4, 0, 2})
	f.Add([]byte{1, 2, 3, 5})
	f.Add([]byte{0, 1, 2, 3, 4, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		c, _ := keyTestConn(t)
		s := &c.spaces[spaceApplication]
		audit := &nonceAuditAEAD{AEAD: s.write.aead, used: make(map[string]bool)}
		s.write.aead = audit
		for i, action := range data {
			if i >= 16 {
				break
			}
			now := time.Now()
			switch action % 6 {
			case 0:
				c.queue(spaceApplication, []byte{1})
			case 1:
				if _, err := c.frames(spaceApplication, append([]byte{0x1a}, bytes.Repeat([]byte{byte(i)}, 8)...), now); err != nil {
					return
				}
			case 2:
				if err := c.flush(now); err != nil {
					return
				}
			case 3:
				c.onTimer(now.Add(2 * c.recovery.basePTO()))
			case 4:
				close(c.listener.closed)
				c.listener.sendQueue = make(chan sendBurst)
				_ = c.transmit(spaceApplication, []byte{1}, nil, now, true)
				c.listener.closed = make(chan struct{})
				c.listener.sendQueue = make(chan sendBurst, 32)
			case 5:
				if s.next > 0 {
					ack := append(appendVarint(nil, s.next-1), 0, 0, 0)
					r := wireReader{data: ack}
					if err := c.acknowledge(spaceApplication, &r, false, now); err != nil {
						return
					}
				}
			}
			for len(c.listener.sendQueue) > 0 {
				for _, p := range (<-c.listener.sendQueue).packets {
					releasePacket(p)
				}
			}
			if audit.repeated || len(s.sent) > 1024 || c.queuedBytes > 512<<10 {
				t.Fatal("send state violated nonce or resource bounds")
			}
		}
	})
}
