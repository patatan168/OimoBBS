// 余力のある予約と、補充待ちで進めない巡回のCPU費用を有界な合成入力で計測する。
package delivery

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func BenchmarkSchedulerReserve(b *testing.B) {
	s, err := New(MaxBudgetBits)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	ip := netip.MustParseAddr("192.0.2.1")
	b.ReportAllocs()
	for b.Loop() {
		permit, err := s.Reserve(b.Context(), ip, 1)
		if err != nil {
			b.Fatal(err)
		}
		permit.Release()
	}
}

func BenchmarkSchedulerSaturatedPump(b *testing.B) {
	for _, count := range []int{40, 2048} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			now := time.Now()
			s := &Scheduler{subjects: make(map[netip.Addr]*subject), rate: 100_000_000, last: now}
			for i := range count {
				ip := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
				r := &request{size: Chunk, ready: make(chan *Permit, 1)}
				s.subjects[ip] = &subject{queue: []*request{r}}
				s.order = append(s.order, ip)
				s.queued++
				if i == 0 {
					s.budgetHead, s.budgetIP = r, ip
					r.budgetBypasses = budgetBypassLimit
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				s.pumpLocked(now)
			}
		})
	}
}
