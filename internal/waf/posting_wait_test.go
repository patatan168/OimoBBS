// 投稿の有限待機・回線制限・頻度制限・取消・設定切替と、解放の競合を検査する。
package waf

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

// occupyPosting は既定の投稿32枠を異なる回線から保持する。
func occupyPosting(t *testing.T, g *TrafficGuard) []func() {
	t.Helper()
	var releases []func()
	for i := range 32 {
		release, d := g.AcquireOperation(netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i+1)), Posting, time.Now())
		if d.Status != 0 {
			t.Fatal(d)
		}
		releases = append(releases, release)
		t.Cleanup(release)
	}
	return releases
}

// awaitPostingWaiters は業務処理の解放より先に、待機登録の完了を同期する。
func awaitPostingWaiters(t *testing.T, g *TrafficGuard, n int) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for g.Stats().Posting.Waiting != n {
		if time.Now().After(until) {
			t.Fatal("待機数が一致しない", g.Stats().Posting, n)
		}
		runtime.Gosched()
	}
}

func TestPostingWaitWakesWithoutIncreasingCapacity(t *testing.T) {
	g := &TrafficGuard{}
	g.Configure(DefaultTrafficSettings(), time.Now())
	releases := occupyPosting(t, g)
	done := make(chan TrafficDecision, 1)
	go func() {
		release, d := g.AcquirePosting(t.Context(), netip.MustParseAddr("198.51.100.1"), time.Now())
		if release != nil {
			defer release()
		}
		done <- d
	}()
	awaitPostingWaiters(t, g, 1)
	if s := g.Stats().Posting; s.Active != 32 || s.Overloaded != 0 || s.Queued != 1 {
		t.Fatal(s)
	}
	releases[0]()
	select {
	case d := <-done:
		if d.Status != 0 {
			t.Fatal(d)
		}
	case <-time.After(time.Second):
		t.Fatal("空きを通知しなかった")
	}
	awaitPostingWaiters(t, g, 0)
	if s := g.Stats().Posting; s.Active > 32 || s.Overloaded != 0 {
		t.Fatal(s)
	}
}

func TestPostingWaitLimitsAndCancellation(t *testing.T) {
	g := &TrafficGuard{}
	g.Configure(DefaultTrafficSettings(), time.Now())
	occupyPosting(t, g)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan TrafficDecision, 32)
	for i := range 32 {
		go func(n int) {
			release, d := g.AcquirePosting(ctx, netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", n+1)), time.Now())
			if release != nil {
				release()
			}
			done <- d
		}(i)
	}
	awaitPostingWaiters(t, g, 32)
	for _, ip := range []string{"198.51.100.1", "203.0.113.1"} {
		release, d := g.AcquirePosting(t.Context(), netip.MustParseAddr(ip), time.Now())
		if release != nil || d.Status != 503 || g.Stats().Posting.Queued != 32 {
			t.Fatal(ip, d, g.Stats())
		}
	}
	cancel()
	for range 32 {
		select {
		case d := <-done:
			if d.Status != 503 {
				t.Fatal(d)
			}
		case <-time.After(time.Second):
			t.Fatal("取消で待機が残った")
		}
	}
	awaitPostingWaiters(t, g, 0)
	if g.Stats().Posting.Active != 32 {
		t.Fatal("待機の取消が実行枠を解放した")
	}
}

func TestPostingWaitSharesIPv6Prefix(t *testing.T) {
	g := &TrafficGuard{}
	g.Configure(DefaultTrafficSettings(), time.Now())
	occupyPosting(t, g)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = g.AcquirePosting(ctx, netip.MustParseAddr("2001:db8:1::1"), time.Now())
	}()
	awaitPostingWaiters(t, g, 1)
	release, d := g.AcquirePosting(t.Context(), netip.MustParseAddr("2001:db8:1::2"), time.Now())
	if release != nil || d.Status != 503 || g.Stats().Posting.Queued != 1 {
		t.Fatal(d, g.Stats())
	}
	cancel()
	<-done
	awaitPostingWaiters(t, g, 0)
}

func TestPostingWaitDoesNotQueueClientOrRateOverload(t *testing.T) {
	for _, reason := range []string{"client_active", "client_rate", "global_rate", "ordinary_active"} {
		t.Run(reason, func(t *testing.T) {
			g := &TrafficGuard{}
			settings := DefaultTrafficSettings()
			if reason == "global_rate" {
				settings.Posting.GlobalRate = 32
				settings.Posting.GlobalBurst = 32
			}
			g.Configure(settings, time.Now())
			ip := netip.MustParseAddr("198.51.100.1")
			if reason == "client_active" || reason == "client_rate" {
				count := 8
				if reason == "client_rate" {
					count = 30
				}
				for range count {
					release, d := g.AcquireOperation(ip, Posting, time.Now())
					if d.Status != 0 {
						t.Fatal(d)
					}
					if reason == "client_rate" {
						release()
					} else {
						t.Cleanup(release)
					}
				}
			}
			// 上記で使用した枠も含めて全体上限に達するまで埋める。
			for i := 0; g.Stats().Posting.Active < 32; i++ {
				release, d := g.AcquireOperation(netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i+1)), Posting, time.Now())
				if d.Status != 0 {
					t.Fatal(d)
				}
				t.Cleanup(release)
			}
			if reason == "ordinary_active" {
				for i := 0; g.Stats().Active < 128; i++ {
					release, d := g.AcquireOperation(netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", i+1)), Ordinary, time.Now())
					if d.Status != 0 {
						t.Fatal(d)
					}
					t.Cleanup(release)
				}
			}
			release, d := g.AcquirePosting(t.Context(), ip, time.Now())
			if release != nil || d.Status != 503 || g.Stats().Posting.Queued != 0 {
				t.Fatal(d, g.Stats())
			}
		})
	}
}

func TestPostingWaitTimeoutAndConfigure(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(fmt.Sprint(change), func(t *testing.T) {
			g := &TrafficGuard{}
			g.Configure(DefaultTrafficSettings(), time.Now())
			occupyPosting(t, g)
			done := make(chan TrafficDecision, 1)
			started := time.Now()
			go func() {
				release, d := g.AcquirePosting(t.Context(), netip.MustParseAddr("198.51.100.1"), time.Now())
				if release != nil {
					release()
				}
				done <- d
			}()
			awaitPostingWaiters(t, g, 1)
			want := 503
			if change {
				s := DefaultTrafficSettings()
				s.Enabled = false
				g.Configure(s, time.Now())
				want = 0
			}
			select {
			case d := <-done:
				if d.Status != want {
					t.Fatal(d)
				}
			case <-time.After(time.Second):
				t.Fatal("待機が終了しない")
			}
			if !change && time.Since(started) < postingWaitTimeout {
				t.Fatal("枠解放なしで期限前に拒否した")
			}
			awaitPostingWaiters(t, g, 0)
			if g.Stats().Posting.Active != 32 {
				t.Fatal("設定変更・期限で実行枠が増減した")
			}
		})
	}
}

func TestPostingWaitClientOffKeepsOnlyTotalBound(t *testing.T) {
	g := &TrafficGuard{}
	s := DefaultTrafficSettings()
	s.ClientEnabled = false
	g.Configure(s, time.Now())
	occupyPosting(t, g)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{}, 2)
	for range 2 {
		go func() {
			_, _ = g.AcquirePosting(ctx, netip.MustParseAddr("198.51.100.1"), time.Now())
			done <- struct{}{}
		}()
	}
	awaitPostingWaiters(t, g, 2)
	cancel()
	<-done
	<-done
	awaitPostingWaiters(t, g, 0)
	if len(g.postingWaiters) != 0 || g.Stats().Clients != 0 {
		t.Fatal("回線別OFFで主体を保持した")
	}
}

func TestPostingWaitReleaseRaceDoesNotLoseCapacity(t *testing.T) {
	for range 100 {
		g := &TrafficGuard{}
		g.Configure(DefaultTrafficSettings(), time.Now())
		releases := occupyPosting(t, g)
		start := make(chan struct{})
		done := make(chan TrafficDecision, 1)
		released := make(chan struct{})
		go func() {
			<-start
			release, d := g.AcquirePosting(t.Context(), netip.MustParseAddr("198.51.100.1"), time.Now())
			if release != nil {
				release()
			}
			done <- d
		}()
		go func() { <-start; releases[0](); close(released) }()
		close(start)
		select {
		case d := <-done:
			if d.Status != 0 {
				t.Fatal("判定・登録と同時の枠解放を失った", d)
			}
		case <-time.After(time.Second):
			t.Fatal("枠解放の通知を失った")
		}
		<-released
		for _, release := range releases {
			release()
		}
		if s := g.Stats(); s.Active != 0 || s.Posting.Waiting != 0 {
			t.Fatal("枠・待機が残った", s)
		}
	}
}
