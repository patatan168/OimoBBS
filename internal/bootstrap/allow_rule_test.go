// 許可ルールは一致した指定規制だけを除外し、他の拒否・Cookie必須を緩めない。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAllowRuleComposition(t *testing.T) {
	now := domain.Time(time.Now().UnixNano())
	board := domain.NewID()
	makeRule := func(effect, value string) denialRule {
		return denialRule{ID: domain.NewID(), Revision: 1, Scope: denialScope{"board", board}, Operations: []string{"reply"}, Conditions: []denialCondition{{"body", "contains", value, "deny"}}, Effect: denialEffect{Type: effect}, Starts: now, Expires: now + domain.Time(time.Hour), Reason: "manual", Enabled: true}
	}
	deny := makeRule("deny", "禁止")
	required := makeRule("require_token", "禁止")
	allow := makeRule("allow_rule_ids", "例外")
	allow.Effect.IDs = []domain.ID{deny.ID}
	b := &postingBoard{owner: board, denials: map[domain.ID]compiledDenial{}}
	for _, rule := range []denialRule{deny, required, allow} {
		compiled, e := compileDenial(rule)
		if e != nil {
			t.Fatal(e)
		}
		b.denials[rule.ID] = compiled
	}
	for _, tt := range []struct {
		body             string
		denied, required bool
	}{{"禁止", true, true}, {"禁止 例外", false, true}, {"例外", false, false}} {
		denied, required, e := b.matchingRules(netip.MustParseAddr("192.0.2.1"), postinput.Input{Body: tt.body}, domain.Hash{}, false, now)
		if e != nil || denied != tt.denied || required != tt.required {
			t.Fatal(tt, denied, required, e)
		}
	}
	allow.Enabled = false
	allow.Revision = 2
	compiled, _ := compileDenial(allow)
	b.denials[allow.ID] = compiled
	denied, _, e := b.matchingRules(netip.MustParseAddr("192.0.2.1"), postinput.Input{Body: "禁止 例外"}, domain.Hash{}, false, now)
	if e != nil || !denied {
		t.Fatal("revoked exception weakened deny", e)
	}
}

func TestAllowRuleInputShape(t *testing.T) {
	id := domain.NewID().String()
	for _, tt := range []struct {
		extra string
		valid bool
	}{
		{`,"allow_rule_ids":["` + id + `"]`, true},
		{`,"allow_rule_ids":[]`, false},
		{`,"allow_rule_ids":null`, false},
		{`,"allow_rule_ids":["` + id + `","` + id + `"]`, false},
	} {
		raw := `{"target":"例外","operations":["reply"],"duration_minutes":60,"reason_code":"manual","match":{"field":"body","operator":"contains","effect":"allow_rule_ids"},"extra_conditions":[],"rate_override":null` + tt.extra + `}`
		var in AdminRuleInput
		e := json.Unmarshal([]byte(raw), &in)
		if e == nil {
			e = in.validate()
		}
		if (e == nil) != tt.valid {
			t.Fatal("input shape", tt.valid, e)
		}
	}
}

func TestAllowRuleLifecycle(t *testing.T) {
	cfg, r, board := anonymousAdminFixture(t, "required")
	defer func() { r.Close() }()
	c := newAdminClient(t, r)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/api/v1/boards/" + board.String() + "/rules"
	save := func(input AdminRuleInput, status int) AdminRule {
		t.Helper()
		res, _ := c.rules(board)
		raw, _ := json.Marshal(input)
		response, body := c.request("POST", path, string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
		if response.StatusCode != status {
			t.Fatal("save", response.StatusCode, body)
		}
		if status != 200 {
			return AdminRule{}
		}
		return ruleResponse(t, body)
	}
	deny := save(AdminRuleInput{Target: "禁止", Operations: []string{"create", "reply"}, Minutes: 60, Reason: "manual", Match: &AdminRuleMatch{"body", "contains", "deny"}}, 200)
	input := AdminRuleInput{Target: "例外", Operations: []string{"create", "reply"}, Minutes: 60, Reason: "manual", Match: &AdminRuleMatch{"name", "exact", "allow_rule_ids"}, Allowed: []domain.ID{domain.NewID()}}
	save(input, 422)
	action := "/boards/" + board.String() + "/rules"
	_, page := c.request("GET", action, "", nil)
	fields := ruleCreateFields(t, page)
	fields.Set("target", "例外")
	fields.Set("field", "name")
	fields.Set("operator", "exact")
	fields.Set("effect", "allow_rule_ids")
	fields.Set("operation", "both")
	fields.Set("duration_minutes", "60")
	fields.Set("reason_code", "manual")
	fields.Set("allow_rule_ids", deny.ID.String())
	response, body := c.request("POST", action, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 303 {
		t.Fatal("HTML allow", response.StatusCode, body)
	}
	response, _ = c.request("POST", action, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 303 {
		t.Fatal("HTML replay", response.StatusCode)
	}
	_, list := c.rules(board)
	var allow AdminRule
	for _, rule := range list.Rules {
		if rule.Match.Effect == "allow_rule_ids" {
			allow = rule
		}
	}
	if len(allow.Allowed) != 1 || allow.Allowed[0] != deny.ID {
		t.Fatal("allowed DTO")
	}
	input.Allowed = []domain.ID{allow.ID}
	save(input, 422)
	server, request, cookies := anonymousHTTP(t, r, siteID(r.site.State()))
	defer func() { server.Close() }()
	post := url.Values{"bbs": {"news"}, "FROM": {"例外"}, "subject": {"例外確認"}, "MESSAGE": {"禁止本文"}, "oimo_request_id": {"allow-cookie-required-0001"}}
	request("POST", "/test/bbs.cgi", post)
	token := cookies["oimo_anon"]
	delete(cookies, "oimo_anon")
	_, body = request("POST", "/test/bbs.cgi", post)
	rows, _ := r.rateHistory()
	if token == nil || len(rows) != 0 || !strings.Contains(body, "2ch_X:cookie") {
		t.Fatal("allow bypassed required Cookie")
	}
	cookies["oimo_anon"] = token
	_, body = request("POST", "/test/bbs.cgi", post)
	rows, _ = r.rateHistory()
	if strings.Contains(body, "ERROR:") || len(rows) != 1 || len(rows[0].record.Keys) != 4 {
		t.Fatal("accepted allow lost hard limits", body)
	}
	post.Set("FROM", "一般")
	post.Set("subject", "規制確認")
	post.Set("oimo_request_id", "allow-ordinary-denied-0001")
	request("POST", "/test/bbs.cgi", post)
	_, body = request("POST", "/test/bbs.cgi", post)
	rows, _ = r.rateHistory()
	if !strings.Contains(body, "ERROR:") || len(rows) != 1 {
		t.Fatal("unmatched allow bypass")
	}
	server.Close()
	c.server.Close()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reopen", e)
	}
	var restoredSite siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &restoredSite); err != nil || restoredSite.MinimumReader < 65 {
		t.Fatal("reader declaration")
	}
	b := r.posting[board]
	check := func(want bool) {
		t.Helper()
		denied, _, e := b.matchingRules(netip.MustParseAddr("127.0.0.1"), postinput.Input{Name: "例外", Body: "禁止"}, domain.Hash{}, true, domain.Time(time.Now().UnixNano()))
		if e != nil || denied != want {
			t.Fatal("saved matcher", denied, e)
		}
	}
	check(false)
	// snapshotも対象規制を保持し、循環参照の許可に変換しない。
	for range 2 {
		if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	candidate := filepath.Join(candidateParent(t), "allow-candidate")
	if _, e = r.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal(e)
	}
	r.Close()
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	b = r.posting[board]
	check(false)
	c = newAdminClient(t, r)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	_, list = c.rules(board)
	for _, rule := range list.Rules {
		if rule.ID == allow.ID {
			allow = rule
		}
	}
	response, body = c.request("POST", path+"/"+allow.ID.String()+"/revoke", "{}", http.Header{"Content-Type": {"application/json"}, "If-Match": {allow.ETag()}, "X-CSRF-Token": {allow.RevokeCSRF}, "Idempotency-Key": {domain.NewID().String()}})
	if response.StatusCode != 200 {
		t.Fatal("revoke", response.StatusCode, body)
	}
	check(true)
	// 保存済み除外対象の欠落・許可同士の参照は復旧検査で拒否する。
	delete(b.denials, deny.ID)
	if validateAllowedReferences(b.denials) == nil {
		t.Fatal("missing target accepted")
	}
}

// TestAllowRuleEffectFixture は追加設計の保存例を製品の効果decoderへ渡す。
func TestAllowRuleEffectFixture(t *testing.T) {
	raw, e := os.ReadFile(filepath.Join("..", "..", "docs", "design", "fixtures", "rule-exceptions.json"))
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Schema, Reader int
		Cases          []struct {
			Name   string
			Effect json.RawMessage
			Valid  bool
		}
	}
	if e = json.Unmarshal(raw, &fixture); e != nil || fixture.Schema != 1 || fixture.Reader != 23 {
		t.Fatal(e)
	}
	for _, tt := range fixture.Cases {
		t.Run(tt.Name, func(t *testing.T) {
			var effect denialEffect
			e := strictjson.Decode(tt.Effect, &effect)
			if (e == nil && validRuleEffect(effect)) != tt.Valid {
				t.Fatal("fixture validation", e)
			}
		})
	}
}
