// 制限器の全枠予約・返却・長期境界・同時実行を注入時計で検査する。
package abuse

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func limitSpec(burst uint32) RateSpec { return RateSpec{Tokens: 1, Every: time.Second, Burst: burst} }
func TestLimiterAtomicAndTickets(t *testing.T) {
	l := NewLimiter(10)
	now := time.Unix(0, 0)
	a := RateCharge{Key: "a", Spec: limitSpec(1), Cost: 1}
	b := RateCharge{Key: "b", Spec: limitSpec(1), Cost: 1}
	ticket, e := l.Reserve(now, []RateCharge{a})
	if e != nil {
		t.Fatal(e)
	}
	if e = l.Commit(ticket); e != nil {
		t.Fatal(e)
	}
	if _, e = l.Reserve(now, []RateCharge{b, a}); e == nil {
		t.Fatal("partial reservation accepted")
	}
	ticket, e = l.Reserve(now, []RateCharge{b})
	if e != nil {
		t.Fatal("failed request consumed other key", e)
	}
	if e = l.Release(ticket); e != nil {
		t.Fatal(e)
	}
	if e = l.Release(ticket); !errors.Is(e, ErrRateTicket) {
		t.Fatal("double release", e)
	}
	ticket, e = l.Reserve(now, []RateCharge{b})
	if e != nil {
		t.Fatal(e)
	}
	if e = NewLimiter(10).Commit(ticket); !errors.Is(e, ErrRateTicket) {
		t.Fatal("foreign ticket")
	}
	if e = l.Uncertain(ticket); e != nil {
		t.Fatal(e)
	}
	if e = l.Release(ticket); !errors.Is(e, ErrRateTicket) {
		t.Fatal("unknown refunded")
	}
}
func TestLimiterTimeAndWindow(t *testing.T) {
	l := NewLimiter(10)
	start := time.Unix(0, 0)
	c := RateCharge{Key: "create", Spec: RateSpec{Tokens: 1, Every: 10 * time.Minute, Burst: 1, WindowLimit: 6}, Cost: 1}
	for i := 0; i < 6; i++ {
		ticket, e := l.Reserve(start.Add(time.Duration(i)*10*time.Minute), []RateCharge{c})
		if e != nil {
			t.Fatal(i, e)
		}
		if e = l.Commit(ticket); e != nil {
			t.Fatal(e)
		}
	}
	_, e := l.Reserve(start.Add(time.Hour), []RateCharge{c})
	var limited *RateLimited
	if !errors.As(e, &limited) || limited.RetryAfter != 60 {
		t.Fatal("61 minute boundary", e)
	}
	ticket, e := l.Reserve(start.Add(61*time.Minute), []RateCharge{c})
	if e != nil {
		t.Fatal(e)
	}
	l.Commit(ticket)
	if _, e = l.Reserve(start, []RateCharge{c}); !errors.Is(e, ErrRateClock) {
		t.Fatal("clock reversal", e)
	}
}
func TestLimiterFractionAndConcurrency(t *testing.T) {
	l := NewLimiter(5)
	start := time.Unix(0, 0)
	c := RateCharge{Key: "shared", Spec: RateSpec{Tokens: 60, Every: time.Second, Burst: 1}, Cost: 1}
	ticket, e := l.Reserve(start, []RateCharge{c})
	if e != nil {
		t.Fatal(e)
	}
	l.Commit(ticket)
	for i := 1; i <= 16; i++ {
		if _, e = l.Reserve(start.Add(time.Duration(i)*time.Millisecond), []RateCharge{c}); e == nil {
			t.Fatal("early refill")
		}
	}
	ticket, e = l.Reserve(start.Add(16666667*time.Nanosecond), []RateCharge{c})
	if e != nil {
		t.Fatal("fraction lost", e)
	}
	l.Commit(ticket)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticket, e := l.Reserve(start.Add(time.Second), []RateCharge{c})
			if e == nil {
				accepted.Add(1)
				l.Commit(ticket)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("shared slot", accepted.Load())
	}
}
func TestLimiterCapacityAndPendingWindow(t *testing.T) {
	l := NewLimiter(1)
	now := time.Unix(0, 0)
	c := RateCharge{Key: "a", Spec: RateSpec{Tokens: 1, Every: time.Second, Burst: 1, WindowLimit: 1}, Cost: 1}
	ticket, e := l.Reserve(now, []RateCharge{c})
	if e != nil {
		t.Fatal(e)
	}
	l.Uncertain(ticket)
	if _, e = l.Reserve(now.Add(2*time.Hour), []RateCharge{c}); !errors.Is(e, ErrRateUncertain) {
		t.Fatal("unknown aged out", e)
	}
	l.Prune(now.Add(2 * time.Hour))
	c.Key = "b"
	if _, e = l.Reserve(now.Add(2*time.Hour), []RateCharge{c}); !errors.Is(e, ErrRateCapacity) {
		t.Fatal("evicted unknown", e)
	}
	l = NewLimiter(1)
	ticket, e = l.Reserve(now, []RateCharge{c})
	if e != nil {
		t.Fatal(e)
	}
	l.Commit(ticket)
	l.Prune(now.Add(61 * time.Minute))
	c.Key = "c"
	if _, e = l.Reserve(now.Add(61*time.Minute), []RateCharge{c}); e != nil {
		t.Fatal("idle not pruned", e)
	}
}

// 無効期間の予約返却が、変更前に確定した消費を返してしまわないことを検査する。
func TestDisabledReservationReleasePreservesConsumption(t *testing.T) {
	now := time.Unix(1800000000, 0)
	limiter := NewLimiter(10)
	spec := RateSpec{Tokens: 1, Every: time.Minute, Burst: 1, WindowLimit: 1, TrackWindow: true}
	charge := RateCharge{Key: "subject", Spec: spec, Cost: 1}
	ticket, e := limiter.Reserve(now, []RateCharge{charge})
	if e != nil {
		t.Fatal(e)
	}
	if e = limiter.Commit(ticket); e != nil {
		t.Fatal(e)
	}
	disabled := spec
	disabled.Disabled = true
	if e = limiter.Reconfigure(now, map[string]RateSpec{"subject": disabled}); e != nil {
		t.Fatal(e)
	}
	charge.Spec = disabled
	ticket, e = limiter.Reserve(now, []RateCharge{charge})
	if e != nil {
		t.Fatal(e)
	}
	if e = limiter.Release(ticket); e != nil {
		t.Fatal(e)
	}
	if e = limiter.Reconfigure(now, map[string]RateSpec{"subject": spec}); e != nil {
		t.Fatal(e)
	}
	charge.Spec = spec
	if _, e = limiter.Reserve(now, []RateCharge{charge}); e == nil {
		t.Fatal("disabled failure refunded accepted post")
	}
}
