// 連続暗号文のdatagram境界と、全sender参照がなくなるまでのbuffer所有権を検証する。
package quicv1

import (
	"bytes"
	"testing"
)

func TestCipherBlockOwnershipAndAppendIsolation(t *testing.T) {
	c := &Conn{batching: true}
	var packets []*packetBuffer
	for i := range 16 {
		packet := c.packetStorage(spaceApplication, 1452)
		copy(packet.data, bytes.Repeat([]byte{byte(i + 1)}, 1452))
		packets = append(packets, packet)
	}
	owner := c.cipherBatch
	owner.release()
	c.cipherBatch = nil
	if owner.refs.Load() != 16 {
		t.Fatal("actor released sender storage")
	}
	if got := contiguousCiphertext(packets, len(packets)); len(got) != 16*1452 {
		t.Fatal("contiguous storage not recognized")
	}
	_ = append(packets[0].data, 0xff)
	if packets[1].data[0] != 2 {
		t.Fatal("append crossed the packet boundary")
	}
	for _, packet := range packets[:8] {
		releasePacket(packet)
	}
	if owner.refs.Load() != 8 {
		t.Fatal("unfinished packet ownership lost")
	}
	next := &Conn{batching: true}
	other := next.packetStorage(spaceApplication, 1452)
	if other.owner == owner || contiguousCiphertext([]*packetBuffer{packets[8], other}, 2) != nil {
		t.Fatal("reused live storage or merged unrelated blocks")
	}
	for i, packet := range packets[8:] {
		if !bytes.Equal(packet.data, bytes.Repeat([]byte{byte(i + 9)}, 1452)) {
			t.Fatal("unfinished packet changed")
		}
		releasePacket(packet)
	}
	releasePacket(other)
	next.cipherBatch.release()
}
