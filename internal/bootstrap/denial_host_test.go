// 逆引きの正引き確認済みホストだけを規制し、本文URL・偽PTR・境界を混同しない。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
	"testing"
)

type denialHostResolver struct {
	hostname string
	forward  netip.Addr
}

func (r denialHostResolver) LookupAddr(context.Context, string) ([]string, error) {
	return []string{r.hostname + "."}, nil
}
func (r denialHostResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{r.forward}, nil
}

func TestDenialVerifiedHostMatching(t *testing.T) {
	ip := netip.MustParseAddr("153.140.37.173")
	for _, tt := range []struct {
		name, host, operator string
		forward              netip.Addr
		match                bool
	}{
		{"exact", "subscriber.example.jp", "exact", ip, true},
		{"suffix", "subscriber.example.jp", "suffix", ip, true},
		{"root", "example.jp", "suffix", ip, true},
		{"label-boundary", "evil-example.jp", "suffix", ip, false},
		{"forged-PTR", "subscriber.example.jp", "suffix", netip.MustParseAddr("8.8.8.8"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cache := identity.NewHostCache(denialHostResolver{tt.host, tt.forward})
			defer cache.Close()
			value := "example.jp"
			if tt.operator == "exact" {
				value = "subscriber.example.jp"
			}
			condition := denialCondition{Field: "host", Operator: tt.operator, Value: value, Unknown: "deny"}
			rule := denialRule{ID: domain.NewID(), Revision: 1, Scope: denialScope{"board", domain.NewID()}, Operations: []string{"reply"}, Conditions: []denialCondition{condition}, Effect: denialEffect{Type: "deny"}, Starts: 1, Expires: 1e12, Reason: "abuse", Enabled: true}
			compiled, err := compileDenial(rule)
			if err != nil {
				t.Fatal(err)
			}
			b := postingBoard{networkHosts: cache, denials: map[domain.ID]compiledDenial{rule.ID: compiled}}
			// 未準備時・URLに同じドメインを記載しただけでは一致しない。
			denied, _, err := b.matchingRules(ip, postinput.Input{Body: "https://subscriber.example.jp/"}, domain.Hash{}, false, 2)
			if err != nil || denied {
				t.Fatal("unconfirmed hostname matched")
			}
			cache.Resolve(t.Context(), ip)
			denied, _, err = b.matchingRules(ip, postinput.Input{}, domain.Hash{}, false, 2)
			if err != nil || denied != tt.match {
				t.Fatal("verified host result", denied, err)
			}
		})
	}
	for _, value := range []string{"*.example.jp", "https://example.jp", "example.jp.", "EXAMPLE.JP", "192.0.2.1"} {
		if _, _, err := compileDenialCondition(denialCondition{"host", "suffix", value, "deny"}); err == nil {
			t.Fatal("ambiguous host accepted", value)
		}
	}
	input := AdminRuleInput{Target: "example.jp", Operations: []string{"reply"}, Minutes: 60, Reason: "abuse", Match: &AdminRuleMatch{"host", "suffix", "require_token"}}
	if input.validate() == nil {
		t.Fatal("host rate/cookie effect allowed")
	}
}

func TestAdminHostRulePersistenceReader(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "hostdeny", "ホスト規制")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	get, _ := c.rules(board.ID)
	input := AdminRuleInput{Target: "example.jp", Operations: []string{"create", "reply"}, Minutes: 60, Reason: "abuse", Match: &AdminRuleMatch{"host", "suffix", "deny"}}
	raw, _ := json.Marshal(input)
	path := "/api/v1/boards/" + board.ID.String() + "/rules"
	res, body := c.request("POST", path, string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {get.Header.Get("ETag")}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"host-rule-create-001"}})
	if res.StatusCode != 200 {
		t.Fatal("host rule create", res.StatusCode, body)
	}
	var state siteState
	if json.Unmarshal(repo.site.State().Rows["site:state"].Value, &state) != nil || state.MinimumReader != 64 {
		t.Fatal("host minimum reader")
	}
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("host rule restart", err)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, rules := c.rules(board.ID)
	if len(rules.Rules) != 1 || rules.Rules[0].Match.Field != "host" || rules.Rules[0].Target != "example.jp" {
		t.Fatal("host persisted rule")
	}
}
