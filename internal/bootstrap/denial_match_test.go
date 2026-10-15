// 内容・URL境界・匿名主体の規制と、必須Cookieの実HTTP往復・復旧・解除を検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
	"oimobbs/internal/strictjson"
	"strings"
	"testing"
	"time"
)

func TestContentRuleBoundaries(t *testing.T) {
	now := domain.Time(time.Now().UnixNano())
	subject := domain.Hash{1}
	for _, tc := range []struct {
		field, operator, target string
		input                   postinput.Input
		token                   domain.Hash
		matches                 bool
	}{
		{"body", "contains", "荒らし", postinput.Input{Body: "これが荒らし本文"}, domain.Hash{}, true},
		{"body", "regexp", "(?m)^禁止[0-9]+$", postinput.Input{Body: "前\n禁止123\n後"}, domain.Hash{}, true},
		{"body", "exact", "一致", postinput.Input{Body: "不一致"}, domain.Hash{}, false},
		{"name", "exact", "名無しさん", postinput.Input{Name: "名無しさん"}, domain.Hash{}, true},
		{"mail", "contains", "spam", postinput.Input{Mail: "spam@example.test"}, domain.Hash{}, true},
		{"title", "regexp", "^広告", postinput.Input{Title: "広告です"}, domain.Hash{}, true},
		{"domain", "suffix", "example.test", postinput.Input{Body: "https://a.example.test:443/p"}, domain.Hash{}, true},
		{"domain", "suffix", "example.test", postinput.Input{Body: "https://notexample.test/p"}, domain.Hash{}, false},
		{"domain", "suffix", "example.test", postinput.Input{Body: "https://example.test.attacker.test/p"}, domain.Hash{}, false},
		{"domain", "exact", "example.test", postinput.Input{Body: "https://attacker.test/?next=https://example.test/p"}, domain.Hash{}, false},
		{"domain", "exact", "example.test", postinput.Input{Body: "https://EXAMPLE.TEST./p"}, domain.Hash{}, true},
		{"domain", "exact", "example.test", postinput.Input{Body: "(HTTPS://EXAMPLE.TEST)"}, domain.Hash{}, true},
		{"domain", "exact", "example.test", postinput.Input{Body: "https://example.test@attacker.test/p"}, domain.Hash{}, false},
		{"token", "exact", subject.String(), postinput.Input{}, subject, true},
		{"token", "exact", subject.String(), postinput.Input{}, domain.Hash{}, false},
	} {
		t.Run(tc.field+"_"+tc.operator+"_"+tc.target, func(t *testing.T) {
			rule := denialRule{domain.NewID(), 1, denialScope{"board", domain.NewID()}, []string{"reply"}, []denialCondition{{tc.field, tc.operator, tc.target, "deny"}}, denialEffect{Type: "deny"}, 0, now, now + domain.Time(time.Minute), "spam", true, nil, nil}
			c, e := compileDenial(rule)
			if e != nil {
				t.Fatal(e)
			}
			b := &postingBoard{denials: map[domain.ID]compiledDenial{rule.ID: c}}
			denied, required, e := b.matchingRules(netip.MustParseAddr("192.0.2.1"), tc.input, tc.token, false, now)
			if e != nil || denied != tc.matches || required {
				t.Fatal("match", denied, required, e)
			}
			denied, _, e = b.matchingRules(netip.MustParseAddr("192.0.2.1"), tc.input, tc.token, false, rule.Expires)
			if e != nil || denied {
				t.Fatal("expiry", e)
			}
		})
	}
	for _, tc := range anonymousSettingsFixture(t).Rules {
		if (tc.Input.validate() == nil) != tc.Valid {
			t.Fatal("fixture rule", tc)
		}
	}
	oversized := AdminRuleInput{Target: strings.Repeat("a", 1025), Operations: []string{"reply"}, Minutes: 1, Reason: "spam", Match: &AdminRuleMatch{"body", "contains", "deny"}}
	if oversized.validate() == nil {
		t.Fatal("oversized rule accepted")
	}
	var old AdminRuleInput
	if e := strictjson.Decode([]byte(`{"target":"192.0.2.1","operations":["reply"],"duration_minutes":60,"reason_code":"spam"}`), &old); e == nil {
		t.Fatal("old rule request accepted")
	}
	if strictjson.Decode([]byte(`{"target":"192.0.2.1","operations":["reply"],"duration_minutes":60,"reason_code":"spam","match":null}`), &old) == nil {
		t.Fatal("null matcher")
	}
}

func TestContentRulesHTTPRecoveryAndRevoke(t *testing.T) {
	cfg, repo, board := anonymousAdminFixture(t, "required")
	defer func() { repo.Close() }()
	other, e := repo.CreateBoard(context.Background(), "other", "別板")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/api/v1/boards/" + board.String() + "/rules"
	save := func(input AdminRuleInput, id string) AdminRule {
		res, _ := c.rules(board)
		raw, _ := json.Marshal(input)
		headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {id}}
		res, body := c.request("POST", path, string(raw), headers)
		if res.StatusCode != 200 {
			t.Fatal("rule save", res.StatusCode, body)
		}
		again, againBody := c.request("POST", path, string(raw), headers)
		if again.StatusCode != 200 || againBody == "" {
			t.Fatal("rule replay")
		}
		return ruleResponse(t, body)
	}
	deny := save(AdminRuleInput{Target: "禁止", Operations: []string{"reply"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{"body", "contains", "deny"}}, "content-deny-rule-0001")
	tokenRule := save(AdminRuleInput{Target: "保護", Operations: []string{"create"}, Minutes: 60, Reason: "abuse", Match: &AdminRuleMatch{"title", "contains", "require_token"}}, "content-token-rule-001")
	server, request, cookies := anonymousHTTP(t, repo, siteID(repo.site.State()))
	defer func() { server.Close() }()
	fields := url.Values{"bbs": {"news"}, "subject": {"保護スレ"}, "MESSAGE": {"普通の本文"}, "oimo_request_id": {"content-rule-post-001"}}
	res, page := request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || !strings.Contains(page, "2ch_X:cookie") {
		t.Fatal("challenge", res.StatusCode, page)
	}
	cookie := cookies["oimo_anon"]
	delete(cookies, "oimo_anon")
	request("POST", "/test/bbs.cgi", fields)
	rows, _ := repo.rateHistory()
	if len(rows) != 0 {
		t.Fatal("require_token bypass")
	}
	cookies["oimo_anon"] = cookie
	res, page = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || strings.Contains(page, "ERROR:") {
		t.Fatal("valid token", res.StatusCode, page)
	}
	var key uint64
	for v := range repo.posting[board].threads {
		key = v
	}
	reply := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(key)}, "MESSAGE": {"禁止本文"}, "oimo_request_id": {"content-rule-post-002"}}
	request("POST", "/test/bbs.cgi", reply)
	res, page = request("POST", "/test/bbs.cgi", reply)
	rows, _ = repo.rateHistory()
	if res.StatusCode != 200 || !strings.Contains(page, "ERROR:") || len(rows) != 1 {
		t.Fatal("content deny", res.StatusCode, page, len(rows))
	}
	// 別板には条件規制を配布しない。
	if len(repo.posting[other.ID].denials) != 0 {
		t.Fatal("other board contaminated")
	}
	c.server.Close()
	server.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("recovery", e)
	}
	if len(repo.posting[board].denials) != 2 {
		t.Fatal("rules lost")
	}
	b := repo.posting[board]
	blocked, required, e := b.matchingRules(netip.MustParseAddr("127.0.0.1"), postinput.Input{Body: "禁止本文"}, domain.Hash{}, false, domain.Time(time.Now().UnixNano()))
	if e != nil || !blocked || required {
		t.Fatal("recovered matcher", e)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	_, list := c.rules(board)
	var current AdminRule
	for _, rule := range list.Rules {
		if rule.ID == deny.ID {
			current = rule
		}
	}
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {current.ETag()}, "X-Csrf-Token": {current.RevokeCSRF}, "Idempotency-Key": {"content-rule-revoke-01"}}
	res, page = c.request("POST", path+"/"+deny.ID.String()+"/revoke", "{}", headers)
	if res.StatusCode != 200 {
		t.Fatal("revoke", res.StatusCode, page)
	}
	blocked, _, e = b.matchingRules(netip.MustParseAddr("127.0.0.1"), postinput.Input{Body: "禁止本文"}, domain.Hash{}, false, domain.Time(time.Now().UnixNano()))
	if e != nil || blocked {
		t.Fatal("revoked rule remains", e)
	}
	if e := snapshotBoardValue("board_rule", tokenRule.ID.String(), nil, b.control.State().Rows["board_rule:"+tokenRule.ID.String()].Value); e != nil {
		t.Fatal("rule snapshot", e)
	}
	_, page = c.request("GET", "/boards/"+board.String()+"/rules", "", nil)
	if !strings.Contains(page, "本文リンクのドメイン") || !strings.Contains(page, "Cookie必須") {
		t.Fatal("rule UI")
	}
}
