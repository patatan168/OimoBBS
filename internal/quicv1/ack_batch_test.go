// 満杯の本文packetに入らないACKを同じburstの端数へ同梱し、ACK期限も守る。
package quicv1

import (
	"bytes"
	"testing"
	"time"
)

func TestACKUsesLaterPacketInSameFlush(t *testing.T) {
	for _, tail := range []bool{false, true} {
		t.Run(map[bool]string{false: "standalone", true: "piggyback"}[tail], func(t *testing.T) {
			c := &Conn{ctx: t.Context(), listener: &Listener{sendQueue: make(chan sendBurst, 1), closed: make(chan struct{})}, peerID: make([]byte, 8), recovery: newRecovery(), mtu: 1200}
			defer c.releaseBuffers()
			for i := range c.spaces {
				c.spaces[i] = newNumberSpace()
			}
			s := &c.spaces[spaceApplication]
			_, key, err := initialKeys([]byte("test-CID"))
			if err != nil {
				t.Fatal(err)
			}
			s.write = key
			now := time.Now()
			s.receive(7, now)
			s.ackPending, s.ackAt = true, now
			c.queue(spaceApplication, bytes.Repeat([]byte{1}, 1171))
			if tail {
				c.queue(spaceApplication, []byte{1})
			}
			if err = c.flush(now); err != nil {
				t.Fatal(err)
			}
			burst := <-c.listener.sendQueue
			defer func() {
				for _, packet := range burst.packets {
					releasePacket(packet)
				}
			}()
			if len(burst.packets) != 2 || s.ackPending {
				t.Fatalf("packets=%d pending ACK=%v", len(burst.packets), s.ackPending)
			}
			last := burst.packets[1].data
			payload, _, _, err := key.openPacket(last, 9, 1)
			if err != nil {
				t.Fatal(err)
			}
			if tail {
				if payload[0] != 1 {
					t.Fatal("tail packet missing its reliable frame")
				}
				payload = payload[1:]
			}
			r := wireReader{data: payload}
			for _, want := range []uint64{2, 7} {
				if got, err := r.integer(); err != nil || got != want {
					t.Fatalf("ACK field=%d want=%d error=%v", got, want, err)
				}
			}
		})
	}
}
