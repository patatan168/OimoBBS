// AND規制の入力上限、条件ごとの非一致、実HTTP拒否と耐久復旧・解除を検査する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
	"oimobbs/internal/strictjson"
)

func TestSiteCookieAndCompositeFixtures(t *testing.T) {
	raw, e := os.ReadFile("../../docs/design/fixtures/site-cookie-and-composite-rules.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Modes []struct {
			Input json.RawMessage `json:"input"`
			Valid bool            `json:"valid"`
		} `json:"modes"`
		Rules []struct {
			Input json.RawMessage `json:"input"`
			Valid bool            `json:"valid"`
		} `json:"rules"`
	}
	if e := strictjson.Decode(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	for _, tc := range fixture.Modes {
		var input anonymousAdminInput
		if (strictjson.Decode(tc.Input, &input) == nil) != tc.Valid {
			t.Fatal("mode fixture", string(tc.Input))
		}
	}
	for _, tc := range fixture.Rules {
		var input AdminRuleInput
		valid := strictjson.Decode(tc.Input, &input) == nil && input.validate() == nil
		if valid != tc.Valid {
			t.Fatal("rule fixture", string(tc.Input))
		}
	}
}

func TestCompositeRuleANDAndStrictInput(t *testing.T) {
	input := AdminRuleInput{Target: "192.0.2.0/24", Operations: []string{"reply"}, Minutes: 60, Reason: "spam", Extra: []AdminRuleCondition{{"body", "contains", "宣伝"}, {"domain", "suffix", "example.test"}, {"name", "regexp", "^広告"}}}
	if e := input.validate(); e != nil {
		t.Fatal(e)
	}
	now := domain.Time(time.Now().UnixNano())
	rule := denialRule{domain.NewID(), 1, denialScope{"board", domain.NewID()}, input.Operations, input.conditions(), denialEffect{Type: "deny"}, 0, now, now + domain.Time(time.Hour), "spam", true, nil, nil}
	c, e := compileDenial(rule)
	if e != nil {
		t.Fatal(e)
	}
	b := &postingBoard{denials: map[domain.ID]compiledDenial{rule.ID: c}}
	good := postinput.Input{Name: "広告投稿", Body: "宣伝 https://a.example.test/p"}
	for _, tc := range []struct {
		ip    string
		in    postinput.Input
		match bool
	}{
		{"192.0.2.1", good, true},
		{"192.0.3.1", good, false},
		{"192.0.2.1", postinput.Input{Name: good.Name, Body: "普通 https://a.example.test/p"}, false},
		{"192.0.2.1", postinput.Input{Name: good.Name, Body: "宣伝 https://notexample.test/p"}, false},
		{"192.0.2.1", postinput.Input{Name: "普通", Body: good.Body}, false},
	} {
		denied, required, e := b.matchingRules(netip.MustParseAddr(tc.ip), tc.in, domain.Hash{}, false, now)
		if e != nil || denied != tc.match || required {
			t.Fatal("AND", tc, denied, required, e)
		}
	}
	raw, _ := json.Marshal(input)
	var decoded AdminRuleInput
	if e := strictjson.Decode(raw, &decoded); e != nil || decoded.validate() != nil {
		t.Fatal("roundtrip", e)
	}
	for _, extra := range []string{`null`, `[]`, `[{"field":"body","operator":"contains"}]`, `[{"field":"body","operator":"contains","value":"x","extra":1}]`} {
		raw := fmt.Sprintf(`{"target":"192.0.2.1","operations":["reply"],"duration_minutes":60,"reason_code":"spam","extra_conditions":%s}`, extra)
		if strictjson.Decode([]byte(raw), &decoded) == nil {
			t.Fatal("invalid extra", raw)
		}
	}
	input.Extra = append(input.Extra, input.Extra[0])
	if input.validate() == nil {
		t.Fatal("duplicate")
	}
	input.Extra = make([]AdminRuleCondition, 8)
	if input.validate() == nil {
		t.Fatal("unbounded conditions")
	}
}

func TestCompositeRulesHTTPRecoveryAndRevoke(t *testing.T) {
	cfg, repo, board := anonymousAdminFixture(t, "required")
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := c.rules(board)
	input := AdminRuleInput{Target: "127.0.0.1", Operations: []string{"reply"}, Minutes: 60, Reason: "spam", Extra: []AdminRuleCondition{{"body", "contains", "禁止"}, {"domain", "suffix", "example.test"}}}
	raw, _ := json.Marshal(input)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"composite-rule-save01"}}
	path := "/api/v1/boards/" + board.String() + "/rules"
	res, body := c.request("POST", path, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode, body)
	}
	saved := ruleResponse(t, body)
	if len(saved.Extra) != 2 {
		t.Fatal("missing conditions")
	}
	res, _ = c.request("POST", path, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("fixed retry")
	}
	server := formServer(t, repo, siteID(repo.site.State()), board, true)
	defer server.Close()
	fields := url.Values{"bbs": {"news"}, "subject": {"複数条件"}, "MESSAGE": {"初回本文"}, "oimo_request_id": {"composite-post-first1"}}
	result, e := sendForm(server, fields)
	if e != nil || !result.Accepted {
		t.Fatal("create", result, e)
	}
	fields.Del("subject")
	fields.Set("key", fmt.Sprint(result.Key))
	fields.Set("MESSAGE", "禁止 https://a.example.test/path")
	fields.Set("oimo_request_id", "composite-post-deny01")
	result, e = sendForm(server, fields)
	if e != nil || result.Accepted {
		t.Fatal("compound bypass", result, e)
	}
	fields.Set("MESSAGE", "禁止 https://unrelated.test/path")
	fields.Set("oimo_request_id", "composite-post-allow1")
	result, e = sendForm(server, fields)
	if e != nil || !result.Accepted {
		t.Fatal("one mismatch blocked", result, e)
	}
	server.Close()
	c.server.Close()
	installRuntimeFixture(t, cfg, repo, 20)
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("recovery", e)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	_, list := c.rules(board)
	if len(list.Rules) != 1 || len(list.Rules[0].Extra) != 2 {
		t.Fatal("recovered conditions", list)
	}
	_, page := c.request("GET", "/boards/"+board.String()+"/rules", "", nil)
	if !strings.Contains(page, "追加条件") || !strings.Contains(page, "example.test") {
		t.Fatal("UI conditions")
	}
	current := list.Rules[0]
	headers = http.Header{"Content-Type": {"application/json"}, "If-Match": {current.ETag()}, "X-Csrf-Token": {current.RevokeCSRF}, "Idempotency-Key": {"composite-rule-revoke1"}}
	res, body = c.request("POST", path+"/"+current.ID.String()+"/revoke", "{}", headers)
	if res.StatusCode != 200 {
		t.Fatal("revoke", res.StatusCode, body)
	}
	denied, _, e := repo.posting[board].matchingRules(netip.MustParseAddr("127.0.0.1"), postinput.Input{Body: "禁止 https://example.test"}, domain.Hash{}, false, domain.Time(time.Now().UnixNano()))
	if e != nil || denied {
		t.Fatal("revoked composite active", e)
	}
}

func TestCompositeRuleHTML(t *testing.T) {
	_, repo, board := anonymousAdminFixture(t, "required")
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/boards/" + board.String() + "/rules"
	_, page := c.request("GET", path, "", nil)
	fields := pageFields(page)
	for key, value := range map[string]string{"target": "127.0.0.1", "field": "auto", "operator": "exact", "effect": "deny", "operation": "reply", "duration_minutes": "60", "reason_code": "spam", "extra_field": "body", "extra_operator": "contains", "extra_value": "追加条件試験"} {
		fields.Set(key, value)
	}
	res, page := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("HTML save", res.StatusCode, page)
	}
	_, list := c.rules(board)
	if len(list.Rules) != 1 || len(list.Rules[0].Extra) != 1 {
		t.Fatal("HTML conditions lost", list)
	}
}
