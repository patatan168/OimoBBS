// 遅延生成するHTTP予約期限と、即時付与後の取消・枠回収を検査する。
package delivery

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// onFirstCheckContext は最初のErrを観測した直後に試験側の状態を進める。
type onFirstCheckContext struct {
	context.Context
	afterCheck func()
	once       sync.Once
}

func (c *onFirstCheckContext) Err() error {
	err := c.Context.Err()
	c.once.Do(c.afterCheck)
	return err
}

func TestHTTPImmediateGrantRechecksCancellation(t *testing.T) {
	s, err := New(MaxBudgetBits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &onFirstCheckContext{Context: parent, afterCheck: cancel}
	p, err := s.reserveHTTP(ctx, netip.MustParseAddr("192.0.2.1"), 1000)
	if p != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation after initial check ignored", p, err)
	}
	status := s.Status()
	if status.Reserved != uint64(estimatedWireBytes(1000)) || status.Active != 0 || status.Subjects != 0 || status.Queued != 0 {
		t.Fatal("canceled grant refunded bytes or retained a slot", status)
	}
}

func TestHTTPReservationWaitingDeadline(t *testing.T) {
	for _, shorterParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "http_limit", true: "parent_limit"}[shorterParent], func(t *testing.T) {
			s, err := New(1)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s.mu.Lock()
			s.tokens = 0
			s.mu.Unlock()
			ctx := t.Context()
			if shorterParent {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(20*time.Millisecond))
				defer cancel()
			}
			started := time.Now()
			p, err := s.reserveHTTP(ctx, netip.MustParseAddr("192.0.2.1"), Chunk)
			elapsed := time.Since(started)
			if p != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("reservation exceeded deadline", p, err)
			}
			if !shorterParent && elapsed < 250*time.Millisecond || elapsed > time.Second {
				t.Fatal("incorrect HTTP waiting limit", elapsed)
			}
			if status := s.Status(); status.Reserved != 0 || status.Active != 0 || status.Subjects != 0 || status.Queued != 0 {
				t.Fatal("timed out request retained state", status)
			}
		})
	}
}

func TestReservationExpiredBeforeEntry(t *testing.T) {
	s, err := New(MaxBudgetBits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.reserveUntil(t.Context(), netip.MustParseAddr("192.0.2.1"), 1000, Chunk, time.Now().Add(-time.Second))
	if p != nil || !errors.Is(err, context.DeadlineExceeded) || s.Status().Reserved != 0 {
		t.Fatal("expired reservation admitted", p, err, s.Status())
	}
}

func TestHTTPReservationDeadlineIncludesMutexWait(t *testing.T) {
	s, err := New(MaxBudgetBits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entered := make(chan struct{})
	ctx := &onFirstCheckContext{Context: t.Context(), afterCheck: func() { close(entered) }}
	results := make(chan error, 1)
	s.mu.Lock()
	go func() {
		p, err := s.reserveHTTP(ctx, netip.MustParseAddr("192.0.2.1"), 1000)
		if p != nil {
			p.Release()
		}
		results <- err
	}()
	<-entered
	// HTTP期限の起算後にmutexを保持し、待機contextの作成時から数え直さないことを確認する。
	timer := time.NewTimer(300 * time.Millisecond)
	<-timer.C
	s.mu.Unlock()
	if err := <-results; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("mutex wait extended HTTP deadline", err)
	}
	if status := s.Status(); status.Active != 0 || status.Queued != 0 || status.Subjects != 0 {
		t.Fatal("expired grant retained state", status)
	}
}

func TestHTTPQueuedReservationNotification(t *testing.T) {
	for _, mode := range []string{"drain", "cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			s, err := New(MaxBudgetBits)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ip := netip.MustParseAddr("192.0.2.1")
			var held []*Permit
			for range 4 {
				p, err := s.reserveHTTP(t.Context(), ip, 1000)
				if err != nil {
					t.Fatal(err)
				}
				held = append(held, p)
				defer p.Release()
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			results := make(chan error, 24)
			for range cap(results) {
				go func() {
					p, err := s.reserveHTTP(ctx, ip, 1000)
					if p != nil {
						p.Release()
					}
					results <- err
				}()
			}
			// 4枠を保持して全予約の登録を観測し、通知と取消の競合を再現する。
			deadline := time.Now().Add(time.Second)
			for {
				q, _, _ := s.Stats()
				if q == cap(results) {
					break
				}
				if time.Until(deadline) <= 0 {
					t.Fatal("requests did not queue", q)
				}
				time.Sleep(time.Millisecond)
			}
			var want error
			if mode == "cancel" {
				cancel()
				want = context.Canceled
			}
			if mode == "close" {
				s.Close()
				want = ErrClosed
			}
			for _, p := range held {
				p.Release()
			}
			for range cap(results) {
				if err := <-results; !errors.Is(err, want) {
					t.Fatal("notification lost or wrong result", err, want)
				}
			}
			status := s.Status()
			if status.Active != 0 || status.Subjects != 0 || status.Queued != 0 {
				t.Fatal("queue or grant leaked", status)
			}
			if mode == "drain" && status.Reserved != uint64(28*estimatedWireBytes(1000)) {
				t.Fatal("queued send bypassed accounting", status)
			}
		})
	}
}
