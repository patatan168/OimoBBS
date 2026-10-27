// 頻度・瞬間集中・検索・同時実行・主体上限を、実時間待機なしで検証する。
package waf

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func trafficFixture() (*TrafficGuard, time.Time) {
	g := &TrafficGuard{}
	now := time.Unix(1800000000, 0)
	g.Configure(DefaultTrafficSettings(), now)
	return g, now
}
func acquireRelease(t *testing.T, g *TrafficGuard, ip string, search bool, now time.Time) TrafficDecision {
	t.Helper()
	release, d := g.Acquire(netip.MustParseAddr(ip), search, now)
	if release != nil {
		release()
	}
	return d
}
func TestTrafficLenientBurstAndRecovery(t *testing.T) {
	g, now := trafficFixture()
	for range 180 {
		if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 0 {
			t.Fatal(d)
		}
	}
	for range 10 {
		if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 429 || d.RetryAfter != 1 {
			t.Fatal(d)
		}
	}
	if d := acquireRelease(t, g, "192.0.2.2", false, now); d.Status != 0 {
		t.Fatal("neighbor affected", d)
	}
	if d := acquireRelease(t, g, "192.0.2.1", false, now.Add(20*time.Millisecond)); d.Status != 0 {
		t.Fatal("refill", d)
	}
	if d := acquireRelease(t, g, "192.0.2.1", false, now.Add(-time.Second)); d.Status != 429 {
		t.Fatal("clock rollback", d)
	}
}
func TestTrafficGlobalAndSearch(t *testing.T) {
	g, now := trafficFixture()
	for n := range 600 {
		ip := fmt.Sprintf("198.18.%d.%d", n/256, n%256)
		if d := acquireRelease(t, g, ip, false, now); d.Status != 0 {
			t.Fatal(n, d)
		}
	}
	if d := acquireRelease(t, g, "203.0.113.1", false, now); d.Status != 503 {
		t.Fatal("distributed flood", d)
	}
	g, now = trafficFixture()
	for range 10 {
		if d := acquireRelease(t, g, "192.0.2.1", true, now); d.Status != 0 {
			t.Fatal(d)
		}
	}
	if d := acquireRelease(t, g, "192.0.2.1", true, now); d.Status != 429 {
		t.Fatal("search rate", d)
	}
	if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 0 {
		t.Fatal("ordinary read penalized", d)
	}
	for n := range 14 {
		if d := acquireRelease(t, g, fmt.Sprintf("192.0.2.%d", n+2), true, now); d.Status != 0 {
			t.Fatal(d)
		}
	}
	if d := acquireRelease(t, g, "203.0.113.2", true, now); d.Status != 503 {
		t.Fatal("distributed search flood", d)
	}
}
func TestTrafficConcurrencyAndLiveConfiguration(t *testing.T) {
	g, now := trafficFixture()
	settings := DefaultTrafficSettings()
	settings.ClientConcurrent = 2
	settings.GlobalConcurrent = 3
	settings.SearchConcurrent = 1
	g.Configure(settings, now)
	a, d := g.Acquire(netip.MustParseAddr("192.0.2.1"), true, now)
	if d.Status != 0 {
		t.Fatal(d)
	}
	if d := acquireRelease(t, g, "192.0.2.2", true, now); d.Status != 503 {
		t.Fatal("search concurrent", d)
	}
	b, d := g.Acquire(netip.MustParseAddr("192.0.2.1"), false, now)
	if d.Status != 0 {
		t.Fatal(d)
	}
	if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 429 {
		t.Fatal("client concurrent", d)
	}
	c, d := g.Acquire(netip.MustParseAddr("192.0.2.2"), false, now)
	if d.Status != 0 {
		t.Fatal(d)
	}
	if d := acquireRelease(t, g, "192.0.2.3", false, now); d.Status != 503 {
		t.Fatal("global concurrent", d)
	}
	settings.GlobalConcurrent = 2
	g.Configure(settings, now)
	a()
	a()
	if g.Stats().Active != 2 {
		t.Fatal("release not idempotent")
	}
	if d := acquireRelease(t, g, "192.0.2.3", false, now); d.Status != 503 {
		t.Fatal("config reset active requests", d)
	}
	b()
	c()
	if stats := g.Stats(); stats.Active != 0 || stats.SearchActive != 0 {
		t.Fatal(stats)
	}
}
func TestTrafficIPv6CapacityAndExpiry(t *testing.T) {
	g, now := trafficFixture()
	for n := range 180 {
		ip := fmt.Sprintf("2001:db8::%x", n+1)
		if d := acquireRelease(t, g, ip, false, now); d.Status != 0 {
			t.Fatal(d)
		}
	}
	if d := acquireRelease(t, g, "2001:db8::ffff", false, now); d.Status != 429 {
		t.Fatal("IPv6 rotation bypass", d)
	}
	if d := acquireRelease(t, g, "2001:db8:0:1::1", false, now); d.Status != 0 {
		t.Fatal("other prefix affected", d)
	}
	g, now = trafficFixture()
	settings := DefaultTrafficSettings()
	settings.GlobalRate = 10000
	settings.GlobalBurst = 10000
	g.Configure(settings, now)
	now = now.Add(time.Second)
	held, d := g.Acquire(netip.MustParseAddr("203.0.113.1"), false, now)
	if d.Status != 0 {
		t.Fatal(d)
	}
	for n := range trafficClientLimit - 1 {
		acquireRelease(t, g, fmt.Sprintf("198.18.%d.%d", n/256, n%256), false, now)
	}
	if g.Stats().Clients != trafficClientLimit {
		t.Fatal(g.Stats())
	}
	if d := acquireRelease(t, g, "203.0.113.2", false, now); d.Status != 503 {
		t.Fatal("unbounded table", d)
	}
	if d := acquireRelease(t, g, "203.0.113.2", false, now.Add(trafficIdle)); d.Status != 0 {
		t.Fatal("expired clients not released", d)
	}
	if stats := g.Stats(); stats.Clients != 2 || stats.Active != 1 {
		t.Fatal("active client evicted", stats)
	}
	held()
}
func TestTrafficConfigurationDoesNotRefillDebt(t *testing.T) {
	g, now := trafficFixture()
	for range 180 {
		acquireRelease(t, g, "192.0.2.1", false, now)
	}
	settings := DefaultTrafficSettings()
	settings.ClientRate = 30
	g.Configure(settings, now)
	if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 429 {
		t.Fatal("settings reset consumed budget", d)
	}
	settings.Enabled = false
	g.Configure(settings, now)
	if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 0 {
		t.Fatal("OFF rejected", d)
	}
	settings.Enabled = true
	g.Configure(settings, now)
	if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 429 {
		t.Fatal("toggle reset debt", d)
	}
}
func TestTrafficConcurrentRelease(t *testing.T) {
	g, now := trafficFixture()
	release, d := g.Acquire(netip.MustParseAddr("192.0.2.1"), true, now)
	if d.Status != 0 {
		t.Fatal(d)
	}
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() { release(); _ = g.Stats() })
	}
	workers.Wait()
	if stats := g.Stats(); stats.Active != 0 || stats.SearchActive != 0 {
		t.Fatal(stats)
	}
}

func TestTrafficOutOfOrderClockDoesNotRejectOrRefill(t *testing.T) {
	g, now := trafficFixture()
	later := now.Add(time.Second)
	if d := acquireRelease(t, g, "192.0.2.1", false, later); d.Status != 0 {
		t.Fatal(d)
	}
	// 別goroutineが先に枠を得た後に、以前に取得した時刻で到着しても誤拒否しない。
	for range 179 {
		if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 0 {
			t.Fatal(d)
		}
	}
	if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 429 {
		t.Fatal("clock rollback created credit", d)
	}
}

func TestTrafficConcurrentConfigure(t *testing.T) {
	_, now := trafficFixture()
	g := &TrafficGuard{}
	settings := DefaultTrafficSettings()
	settings.ClientRate = 10000
	settings.ClientBurst = 100000
	settings.GlobalRate = 100000
	settings.GlobalBurst = 200000
	g.Configure(settings, now)
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Go(func() {
			ip := netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", worker+1))
			for range 1000 {
				release, decision := g.Acquire(ip, false, now)
				if decision.Status != 0 {
					t.Errorf("unexpected rejection: %+v", decision)
					return
				}
				release()
			}
		})
	}
	workers.Go(func() {
		for range 100 {
			g.Configure(settings, now)
			_ = g.Stats()
		}
	})
	workers.Wait()
	if stats := g.Stats(); stats.Active != 0 || stats.RateLimited != 0 || stats.Overloaded != 0 {
		t.Fatal(stats)
	}
}

func TestTrafficRejectedFloodDoesNotFillSourceTable(t *testing.T) {
	g, now := trafficFixture()
	for n := range 600 {
		if d := acquireRelease(t, g, fmt.Sprintf("198.18.%d.%d", n/256, n%256), false, now); d.Status != 0 {
			t.Fatal(d)
		}
	}
	for n := range 10000 {
		if d := acquireRelease(t, g, fmt.Sprintf("198.19.%d.%d", n/256, n%256), false, now); d.Status != 503 {
			t.Fatal(d)
		}
	}
	if stats := g.Stats(); stats.Clients != 600 {
		t.Fatal("rejected sources consumed memory", stats)
	}
	if d := acquireRelease(t, g, "192.0.2.1", false, now.Add(time.Second)); d.Status != 0 {
		t.Fatal("new legitimate source failed to recover", d)
	}
}
