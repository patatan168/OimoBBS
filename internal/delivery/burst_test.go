// 帯域に応じた短いburstと、小応答の追越し・大応答の進行を確定時刻で検査する。
package delivery

import (
	"net/netip"
	"testing"
	"time"
)

func TestRateSizedBurst(t *testing.T) {
	for _, tc := range []struct{ rate, want uint64 }{{1, 32768}, {80000000, 32768}, {100000000, 32768}, {1000000000, 250000}} {
		s, err := New(tc.rate)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.Status().BurstBytes; got != tc.want {
			t.Fatal(tc.rate, got, tc.want)
		}
		s.Close()
	}
}

func TestCongestedBodyChunks(t *testing.T) {
	s := &Scheduler{rate: 80000000}
	for _, tc := range []struct{ queued, want int }{{0, 16384}, {31, 15625}, {127, 3906}, {2047, 512}} {
		s.queued = tc.queued
		if got := s.bodyChunk(); got != tc.want {
			t.Fatal(tc.queued, got, tc.want)
		}
	}
}

func TestSmallResponsesBypassBoundedHead(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	head := &request{size: Chunk, ready: make(chan *Permit, 1)}
	sub := &subject{queue: []*request{head}}
	for range 5 {
		sub.queue = append(sub.queue, &request{size: 500, ready: make(chan *Permit, 1)})
	}
	s := &Scheduler{subjects: map[netip.Addr]*subject{ip: sub}, order: []netip.Addr{ip}, queued: 6, rate: 80000000, last: now, wake: make(chan struct{}, 1)}
	for i := range 5 {
		s.tokens = 500 * 8 * uint64(time.Second)
		small := sub.queue[1]
		s.pumpLocked(now)
		if i < 4 {
			if small.permit == nil || head.permit != nil {
				t.Fatal("small response blocked by bulk", i)
			}
			small.permit.Release()
		} else if small.permit != nil {
			t.Fatal("large response starved")
		}
	}
	s.tokens = Chunk * 8 * uint64(time.Second)
	s.pumpLocked(now)
	if head.permit == nil {
		t.Fatal("large response cannot resume")
	}
	head.permit.Release()
	if s.queued != 1 {
		t.Fatal("queue accounting", s.queued)
	}
	s.cancel(ip, sub.queue[0])
	if queued, subjects, active := s.Stats(); queued != 0 || subjects != 0 || active != 0 {
		t.Fatal("cancel retained burst queue", queued, subjects, active)
	}
}
