// 処理別枠の独立性・拒否時の非消費・設定切替・回復を合成時刻で検証する。
package waf

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func workAcquire(t *testing.T, g *TrafficGuard, op Operation, ip string, now time.Time) TrafficDecision {
	t.Helper()
	release, d := g.AcquireOperation(netip.MustParseAddr(ip), op, now)
	if release != nil {
		release()
	}
	return d
}

func TestOperationBurstIsolationAndRecovery(t *testing.T) {
	for _, op := range []Operation{Posting, Reports, Authentication} {
		t.Run(fmt.Sprint(op), func(t *testing.T) {
			g, now := trafficFixture()
			limit := workLimits(DefaultTrafficSettings())[int(op-Posting)]
			for range limit.clientBurst {
				if d := workAcquire(t, g, op, "192.0.2.1", now); d.Status != 0 {
					t.Fatal(d)
				}
			}
			before := g.clients[netip.MustParsePrefix("192.0.2.1/32")].requests.tokens
			for range 3 {
				if d := workAcquire(t, g, op, "192.0.2.1", now); d.Status != 429 {
					t.Fatal(d)
				}
			}
			if g.clients[netip.MustParsePrefix("192.0.2.1/32")].requests.tokens != before {
				t.Fatal("rejection consumed ordinary tokens")
			}
			for _, other := range []Operation{Ordinary, Search, Posting, Reports, Authentication} {
				if other != op {
					if d := workAcquire(t, g, other, "192.0.2.1", now); d.Status != 0 {
						t.Fatal("other work penalized", other, d)
					}
				}
			}
			if d := workAcquire(t, g, op, "192.0.2.2", now); d.Status != 0 {
				t.Fatal("neighbor penalized", d)
			}
			g.Configure(DefaultTrafficSettings(), now)
			if d := workAcquire(t, g, op, "192.0.2.1", now); d.Status != 429 {
				t.Fatal("configure reset tokens", d)
			}
			if d := workAcquire(t, g, op, "192.0.2.1", now.Add(time.Second)); d.Status != 0 {
				t.Fatal("no recovery", d)
			}
		})
	}
}

func TestOperationConcurrencyAndGlobalRate(t *testing.T) {
	for _, op := range []Operation{Posting, Reports, Authentication} {
		g, now := trafficFixture()
		limit := workLimits(DefaultTrafficSettings())[int(op-Posting)]
		var release []func()
		for n := range limit.globalConcurrent {
			f, d := g.AcquireOperation(netip.MustParseAddr(fmt.Sprintf("198.18.0.%d", n+1)), op, now)
			if d.Status != 0 {
				t.Fatal(op, n, d)
			}
			release = append(release, f)
		}
		clients := g.Stats().Clients
		if d := workAcquire(t, g, op, "203.0.113.1", now); d.Status != 503 {
			t.Fatal(op, d)
		}
		if g.Stats().Clients != clients {
			t.Fatal("global refusal remembered new client")
		}
		g.Configure(DefaultTrafficSettings(), now)
		if d := workAcquire(t, g, op, "203.0.113.1", now); d.Status != 503 {
			t.Fatal("configure reset active", d)
		}
		for _, f := range release {
			f()
			f()
		}
		for n := limit.globalConcurrent; n < limit.globalBurst; n++ {
			if d := workAcquire(t, g, op, fmt.Sprintf("198.18.1.%d", n+1), now); d.Status != 0 {
				t.Fatal(op, n, d)
			}
		}
		if d := workAcquire(t, g, op, "203.0.113.1", now); d.Status != 503 {
			t.Fatal("global burst", op, d)
		}
		if d := workAcquire(t, g, Ordinary, "203.0.113.1", now); d.Status != 0 {
			t.Fatal("ordinary affected", d)
		}
		if d := workAcquire(t, g, op, "203.0.113.1", now.Add(time.Second)); d.Status != 0 {
			t.Fatal("global recovery", d)
		}
	}
}

func TestOperationClientConcurrencyAndLazyMemory(t *testing.T) {
	g, now := trafficFixture()
	ip := netip.MustParseAddr("192.0.2.1")
	if d := workAcquire(t, g, Ordinary, ip.String(), now); d.Status != 0 {
		t.Fatal(d)
	}
	if g.clients[netip.PrefixFrom(ip, 32)].work != nil {
		t.Fatal("ordinary allocated work state")
	}
	release, d := g.AcquireOperation(ip, Authentication, now)
	if d.Status != 0 {
		t.Fatal(d)
	}
	if d := workAcquire(t, g, Authentication, ip.String(), now); d.Status != 429 {
		t.Fatal("client concurrency", d)
	}
	if stats := g.Stats().Authentication; stats.Active != 1 || stats.RateLimited != 1 {
		t.Fatal(stats)
	}
	release()
	if g.Stats().Authentication.Active != 0 {
		t.Fatal("active leak")
	}
}

func TestOperationSettingsClampAndToggle(t *testing.T) {
	g, now := trafficFixture()
	s := DefaultTrafficSettings()
	s.ClientRate, s.ClientBurst, s.ClientConcurrent = 1, 2, 1
	s.GlobalRate, s.GlobalBurst, s.GlobalConcurrent = 2, 4, 2
	s.SearchRate, s.SearchBurst = 1, 2
	s.SearchGlobalRate, s.SearchGlobalBurst, s.SearchConcurrent = 1, 2, 1
	g.Configure(s, now)
	for _, v := range g.workLimits {
		if v != (workLimit{1, 2, 1, 2, 4, 2}) {
			t.Fatal("did not clamp to normal limits", v)
		}
	}
	for range 2 {
		if d := workAcquire(t, g, Authentication, "192.0.2.1", now); d.Status != 0 {
			t.Fatal(d)
		}
	}
	s.Enabled = false
	g.Configure(s, now)
	if d := workAcquire(t, g, Authentication, "192.0.2.1", now); d.Status != 0 {
		t.Fatal("disabled", d)
	}
	s.Enabled = true
	g.Configure(s, now)
	if d := workAcquire(t, g, Authentication, "192.0.2.1", now); d.Status != 429 {
		t.Fatal("toggle reset tokens", d)
	}
	if d := workAcquire(t, g, Authentication, "192.0.2.1", now.Add(time.Second)); d.Status != 0 {
		t.Fatal("refill", d)
	}
}

func TestOperationConcurrentReleaseAndConfigure(t *testing.T) {
	g, now := trafficFixture()
	var workers sync.WaitGroup
	for n := range 16 {
		workers.Go(func() {
			ip := netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", n+1))
			for k := range 30 {
				if k%10 == 0 {
					g.Configure(DefaultTrafficSettings(), now)
				}
				release, d := g.AcquireOperation(ip, Posting+Operation(k%workCount), now)
				if release != nil {
					release()
					release()
				} else if d.Status != 429 && d.Status != 503 {
					t.Error(d)
				}
			}
		})
	}
	workers.Wait()
	stats := g.Stats()
	if stats.Active != 0 || stats.Posting.Active != 0 || stats.Reports.Active != 0 || stats.Authentication.Active != 0 {
		t.Fatal("leaked work", stats)
	}
}
