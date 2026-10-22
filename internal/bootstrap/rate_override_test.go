// 条件付き投稿枠は通常枠と一括予約し、補充/長期窓の復元範囲を超える入力を拒否する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/abuse"
	"testing"
	"time"
)

func TestRateOverrideBounds(t *testing.T) {
	for _, tt := range []struct {
		v     AdminRateOverride
		valid bool
	}{
		{AdminRateOverride{RefillSeconds: 10, Burst: 3, WindowLimit: 0}, true},
		{AdminRateOverride{RefillSeconds: 3600, Burst: 1, WindowLimit: 1}, true},
		{AdminRateOverride{RefillSeconds: 0, Burst: 1}, false},
		{AdminRateOverride{RefillSeconds: 3601, Burst: 1}, false},
		{AdminRateOverride{RefillSeconds: 1801, Burst: 2}, false},
		{AdminRateOverride{RefillSeconds: 1, Burst: 0}, false},
	} {
		if tt.v.valid() != tt.valid {
			t.Fatal(tt)
		}
	}
}
func TestRateOverrideAtomicBudget(t *testing.T) {
	now := time.Now()
	l := abuse.NewLimiter(10)
	normal := abuse.RateCharge{Key: "normal", Spec: abuse.RateSpec{Tokens: 1, Every: time.Second, Burst: 3}, Cost: 1}
	override := abuse.RateCharge{Key: "override", Spec: AdminRateOverride{RefillSeconds: 10, Burst: 1}.spec(), Cost: 1}
	ticket, e := l.Reserve(now, []abuse.RateCharge{normal, override})
	if e != nil || l.Commit(ticket) != nil {
		t.Fatal(e)
	}
	if _, e = l.Reserve(now, []abuse.RateCharge{normal, override}); e == nil {
		t.Fatal("override bypass")
	}
	for range 2 {
		ticket, e = l.Reserve(now, []abuse.RateCharge{normal})
		if e != nil || l.Commit(ticket) != nil {
			t.Fatal("partial normal consumption", e)
		}
	}
	if _, e = l.Reserve(now, []abuse.RateCharge{normal}); e == nil {
		t.Fatal("normal cap bypass")
	}
}

func TestRateOverrideInput(t *testing.T) {
	for _, tt := range []struct {
		effect string
		rate   string
		valid  bool
	}{
		{"rate_override", `{"refill_seconds":10,"burst":2,"window_limit":6}`, true},
		{"rate_override", `null`, false},
		{"rate_override", `{"refill_seconds":1801,"burst":2,"window_limit":0}`, false},
		{"deny", `{"refill_seconds":10,"burst":2,"window_limit":6}`, false},
	} {
		raw := `{"target":"宣伝","operations":["reply"],"duration_minutes":60,"reason_code":"spam","match":{"field":"body","operator":"contains","effect":"` + tt.effect + `"},"extra_conditions":[],"allow_rule_ids":[],"rate_override":` + tt.rate + `}`
		var input AdminRuleInput
		e := json.Unmarshal([]byte(raw), &input)
		if e == nil {
			e = input.validate()
		}
		if (e == nil) != tt.valid {
			t.Fatal("override input", tt.effect, tt.valid, e)
		}
	}
}
