// RFC整数・packet番号とRFC9001公開ベクトルを用い、既存実装から独立して検証する。
package quicv1

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestVarintBoundaries(t *testing.T) {
	for _, v := range []uint64{0, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, maxVarint} {
		encoded := appendVarint(nil, v)
		r := wireReader{data: encoded}
		got, err := r.integer()
		if err != nil || got != v || r.left() != 0 {
			t.Fatal(v, got, err)
		}
		for n := 0; n < len(encoded); n++ {
			r := wireReader{data: encoded[:n]}
			if _, err := r.integer(); err == nil {
				t.Fatal("truncated varint accepted", n)
			}
		}
	}
}
func TestInitialKeyVector(t *testing.T) {
	c, s, err := initialKeys(mustHex("8394c8f03e515708"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(c.iv) != "fa044b2f42a3fd3b46fb255c" || hex.EncodeToString(s.iv) != "0ac1493ca1905853b0bba03e" {
		t.Fatal("RFC9001 initial IV", hex.EncodeToString(c.iv), hex.EncodeToString(s.iv))
	}
}
func TestRetryIntegrityVector(t *testing.T) {
	retry := mustHex("ff000000010008f067a5502a4262b5746f6b656e")
	tag := retryIntegrity(mustHex("8394c8f03e515708"), retry)
	if hex.EncodeToString(tag) != "04a265ba2eff4d829058fb3f0f2496ba" {
		t.Fatal(hex.EncodeToString(tag))
	}
}
func TestPacketProtectionRoundTrip(t *testing.T) {
	k, _, _ := initialKeys([]byte("12345678"))
	header := append([]byte{0x43}, []byte("abcdefgh")...)
	header = append(header, 0, 0, 0, 17)
	data := bytes.Repeat([]byte{1}, 32)
	packet, err := k.sealPacket(header, data, 17, 9)
	if err != nil {
		t.Fatal(err)
	}
	got, pn, _, err := k.openPacket(packet, 9, 0)
	if err != nil || pn != 17 || !bytes.Equal(got, data) {
		t.Fatal(pn, err)
	}
	packet[len(packet)-1] ^= 1
	if _, _, _, err = k.openPacket(packet, 9, 0); err == nil {
		t.Fatal("modified AEAD accepted")
	}
}
func FuzzVarint(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{0xc0, 0, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := wireReader{data: data}
		v, err := r.integer()
		if err != nil {
			return
		}
		again := wireReader{data: appendVarint(nil, v)}
		got, err := again.integer()
		if err != nil || got != v {
			t.Fatal("round trip")
		}
	})
}

func TestKeyUpdateRetainsHeaderProtection(t *testing.T) {
	k, _, _ := initialKeys([]byte("12345678"))
	next, err := k.next()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k.iv, next.iv) {
		t.Fatal("packet key did not change")
	}
	sample := bytes.Repeat([]byte{7}, 16)
	a, _ := k.mask(sample)
	b, _ := next.mask(sample)
	if a != b {
		t.Fatal("header protection changed on key update")
	}
}
