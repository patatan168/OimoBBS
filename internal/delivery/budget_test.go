// 有限帯域でも、整数補充・IP別公平性・有界送信枠を維持することを検査する。
package delivery

import (
	"net/netip"
	"testing"
	"time"
)

func TestBudgetRange(t *testing.T) {
	for _, bits := range []uint64{1, 80_000_000, 240_000_000, 400_000_000, 800_000_000, MaxBudgetBits} {
		s, err := New(bits)
		if err != nil {
			t.Fatal(bits, err)
		}
		if s.Status().Budget != bits {
			t.Fatal("budget changed")
		}
		s.Close()
	}
	for _, bits := range []uint64{0, MaxBudgetBits + 1, ^uint64(0)} {
		if _, err := New(bits); err == nil {
			t.Fatal("overflowing budget accepted", bits)
		}
	}
}

func TestHighBudgetRefillTiming(t *testing.T) {
	for _, tc := range []struct {
		rate uint64
		want time.Duration
	}{
		{1_000_000_000, 131072 * time.Nanosecond},
		{100_000_000, 1310720 * time.Nanosecond},
		{80_000_000, 1638400 * time.Nanosecond},
		{1_000_000, 10 * time.Millisecond},
	} {
		ip := netip.MustParseAddr("192.0.2.1")
		s := &Scheduler{subjects: map[netip.Addr]*subject{ip: {queue: []*request{{size: Chunk}}}}, rate: tc.rate}
		if got := s.refillWaitLocked(); got != tc.want {
			t.Fatal(tc.rate, got, tc.want)
		}
	}
}
