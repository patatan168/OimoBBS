// offset再構成・ACK区間・RTT/PTOをネットワーク待ちなしで検査する。
package quicv1

import (
	"bytes"
	"testing"
	"time"
)

func TestReassemblyBounds(t *testing.T) {
	r := reassembly{limit: 16}
	if _, err := r.insert(3, []byte("def"), true); err != nil {
		t.Fatal(err)
	}
	if r.pop() != nil {
		t.Fatal("gap bypassed")
	}
	if _, err := r.insert(0, []byte("abcde"), false); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for {
		p := r.pop()
		if p == nil {
			break
		}
		got = append(got, p...)
	}
	if !bytes.Equal(got, []byte("abcdef")) {
		t.Fatal(string(got))
	}
	if _, err := r.insert(6, []byte("x"), false); err == nil {
		t.Fatal("final size bypassed")
	}
	r = reassembly{limit: 2}
	if _, err := r.insert(0, []byte("abc"), false); err == nil {
		t.Fatal("budget bypassed")
	}
}
func TestReassemblyRejectsChangedOverlap(t *testing.T) {
	r := reassembly{limit: 100}
	r.insert(3, []byte("abc"), false)
	if _, err := r.insert(4, []byte("XYZ"), false); err == nil {
		t.Fatal("changed retransmit accepted")
	}
}
func TestACKRangeEncoding(t *testing.T) {
	s := newNumberSpace()
	now := time.Now()
	for _, pn := range []uint64{1, 2, 5, 9, 10} {
		s.receive(pn, now)
	}
	s.ackPending = true
	r := wireReader{data: s.ackFrame(now)}
	want := []uint64{2, 10, 0, 2, 1, 2, 0, 1, 1}
	for _, v := range want {
		got, err := r.integer()
		if err != nil || got != v {
			t.Fatal(v, got, err)
		}
	}
	if r.left() != 0 {
		t.Fatal("trailing data")
	}
}
func TestRecoveryRTTAndCongestion(t *testing.T) {
	r := newRecovery()
	r.updateRTT(100*time.Millisecond, 0, false)
	r.updateRTT(125*time.Millisecond, 25*time.Millisecond, true)
	if r.smoothed != 100*time.Millisecond {
		t.Fatal(r.smoothed)
	}
	now := time.Now()
	r.inFlight = 1200
	r.lost(sentPacket{at: now.Add(-time.Second), size: 1200}, now)
	if r.cwnd != 6000 || r.inFlight != 0 {
		t.Fatal(r)
	}
	r.ptoCount = 1
	if r.pto() <= 100*time.Millisecond {
		t.Fatal("PTO backoff missing")
	}
}

// 再送backoffがidleの基準を変えないことを検査する。
func TestIdlePTOIgnoresBackoff(t *testing.T) {
	r := newRecovery()
	base := r.basePTO()
	r.ptoCount = 6
	if r.basePTO() != base || r.pto() <= base {
		t.Fatal("idle timeout extended by backoff")
	}
}
