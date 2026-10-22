// 回線別の無効化が全体枠・攻撃対策の処理枠・再有効化時の消費量を迂回しないことを確認する。
package waf

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"oimobbs/internal/strictjson"
	"testing"
	"time"
)

func TestTrafficClientOffKeepsGlobalLimits(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		op    Operation
		burst int
	}{{Ordinary, 600}, {Search, 24}, {Posting, 120}, {Reports, 16}, {Authentication, 8}} {
		t.Run(fmt.Sprint(tc.op), func(t *testing.T) {
			s := DefaultTrafficSettings()
			s.ClientEnabled = false
			g := &TrafficGuard{}
			g.Configure(s, now)
			for i := range tc.burst + 1 {
				release, decision := g.AcquireOperation(netip.MustParseAddr("192.0.2.1"), tc.op, now)
				if i == tc.burst {
					if decision.Status != 503 {
						t.Fatal("全体枠の迂回", decision)
					}
					break
				}
				if decision.Status != 0 {
					t.Fatal("回線別枠が残った", i, decision)
				}
				release()
				release()
			}
			if stats := g.Stats(); stats.Clients != 0 || stats.Active != 0 || stats.SearchActive != 0 || stats.Posting.Active != 0 || stats.Authentication.Active != 0 || stats.Reports.Active != 0 {
				t.Fatal("無効中の主体保持・枠解放", stats)
			}
		})
	}
}

func TestTrafficClientToggleKeepsConsumptionAndActive(t *testing.T) {
	g, now := trafficFixture()
	for range 180 {
		if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 0 {
			t.Fatal(d)
		}
	}
	s := DefaultTrafficSettings()
	s.ClientEnabled = false
	g.Configure(s, now)
	if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 0 {
		t.Fatal(d)
	}
	s.ClientEnabled = true
	g.Configure(s, now)
	if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 429 {
		t.Fatal("切替でトークンが復活した", d)
	}
	g, now = trafficFixture()
	release, decision := g.AcquireOperation(netip.MustParseAddr("192.0.2.1"), Authentication, now)
	if decision.Status != 0 {
		t.Fatal(decision)
	}
	s.ClientEnabled = false
	g.Configure(s, now)
	other, decision := g.AcquireOperation(netip.MustParseAddr("192.0.2.1"), Authentication, now)
	if decision.Status != 0 {
		t.Fatal("無効化しても同時処理の回線枠が残った", decision)
	}
	if _, d := g.AcquireOperation(netip.MustParseAddr("192.0.2.1"), Authentication, now); d.Status != 503 {
		t.Fatal("実行中の全体枠を失った", d)
	}
	release()
	other()
	if stats := g.Stats(); stats.Active != 0 || stats.Authentication.Active != 0 {
		t.Fatal(stats)
	}
}

func TestTrafficClientOffDoesNotRejectUntrackedNetworks(t *testing.T) {
	g, now := trafficFixture()
	for i := range trafficClientLimit {
		g.clients[netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 32)] = &trafficClient{last: now}
	}
	s := DefaultTrafficSettings()
	s.ClientEnabled = false
	g.Configure(s, now)
	if d := acquireRelease(t, g, "192.0.2.1", false, now); d.Status != 0 {
		t.Fatal("無効な回線表の上限で拒否した", d)
	}
	if g.Stats().Clients != trafficClientLimit {
		t.Fatal("無効中に回線を追加した")
	}
}

func TestTrafficClientSwitchStrictCompatibility(t *testing.T) {
	original := DefaultTrafficSettings()
	raw, _ := json.Marshal(original)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "client_enabled")
	legacy, _ := json.Marshal(fields)
	var got TrafficSettings
	if err := strictjson.Decode(legacy, &got); err != nil || got != original {
		t.Fatal("旧値の回線制限が無効になった", err)
	}
	fields["client_enabled"] = json.RawMessage("false")
	off, _ := json.Marshal(fields)
	if err := strictjson.Decode(off, &got); err != nil || got.ClientEnabled {
		t.Fatal("明示OFF", err)
	}
	for _, value := range []string{"null", "0", `"false"`} {
		fields["client_enabled"] = json.RawMessage(value)
		bad, _ := json.Marshal(fields)
		if strictjson.Decode(bad, &got) == nil {
			t.Fatal("不正なスイッチ", value)
		}
	}
}
