// IP/CIDRの境界と、開始・期限・解除・復旧検査を確認する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"net/netip"
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestDenialRuleBoundaries(t *testing.T) {
	for _, raw := range []string{"192.0.2.1/24", "2001:DB8::/32", "::ffff:192.0.2.1", "fe80::1%eth0", "192.168.001.1", " 192.0.2.1", "192.0.2.1/33"} {
		if _, _, e := denialTarget(raw); e == nil {
			t.Fatal("noncanonical target accepted", raw)
		}
	}
	for _, tc := range []struct{ target, inside, outside string }{
		{"192.0.2.1", "::ffff:192.0.2.1", "192.0.2.2"},
		{"192.0.2.0/24", "192.0.2.255", "192.0.3.0"},
		{"2001:db8::/32", "2001:db8:ffff::1", "2001:db9::1"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			prefix, field, e := denialTarget(tc.target)
			if e != nil {
				t.Fatal(e)
			}
			op := "exact"
			if field == "network" {
				op = "cidr"
			}
			starts := domain.Time(time.Now().UnixNano())
			rule := denialRule{domain.NewID(), 1, denialScope{"board", domain.NewID()}, []string{"reply"}, []denialCondition{{field, op, tc.target, "deny"}}, denialEffect{Type: "deny"}, 0, starts, starts + domain.Time(time.Minute), "spam", true, nil, nil}
			c, e := compileDenial(rule)
			if e != nil || c.prefix != prefix {
				t.Fatal(e)
			}
			b := &postingBoard{denials: map[domain.ID]compiledDenial{rule.ID: c}}
			inside, outside := netip.MustParseAddr(tc.inside), netip.MustParseAddr(tc.outside)
			if !errors.Is(b.checkDenials(inside, false, starts), ErrPostingDenied) {
				t.Fatal("start boundary")
			}
			if e := b.checkDenials(outside, false, starts); e != nil {
				t.Fatal("outside blocked", e)
			}
			if e := b.checkDenials(inside, true, starts); e != nil {
				t.Fatal("wrong operation blocked")
			}
			if e := b.checkDenials(inside, false, rule.Expires); e != nil {
				t.Fatal("expiry boundary")
			}
			if !errors.Is(b.checkDenials(inside, false, starts-1), ErrPostingUnavailable) {
				t.Fatal("clock rollback opened rule")
			}
			before, _ := json.Marshal(rule)
			rule.Enabled = false
			rule.Revision = 2
			after, _ := json.Marshal(rule)
			if e := validateDenialRule(rule.ID.String(), before, after); e != nil {
				t.Fatal("revoke", e)
			}
			c, _ = compileDenial(rule)
			b.denials[rule.ID] = c
			if e := b.checkDenials(inside, false, starts); e != nil {
				t.Fatal("revoked rule applied")
			}
			rule.Conditions[0].Value = tc.outside
			changed, _ := json.Marshal(rule)
			if e := validateDenialRule(rule.ID.String(), before, changed); e == nil {
				t.Fatal("revoke changed target")
			}
		})
	}
}
