// URLの宛先表記による投稿規制の迂回を、WAF有効のHTTP投稿と共通規制で検査する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/waf"
)

func TestDomainRuleAliasesHTTPAndGlobal(t *testing.T) {
	_, repo, board := anonymousAdminFixture(t, "required")
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := c.rules(board)
	input := AdminRuleInput{Target: "example.test", Operations: []string{"create", "reply"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{"domain", "suffix", "deny"}}
	raw, _ := json.Marshal(input)
	res, body := c.request("POST", "/api/v1/boards/"+board.String()+"/rules", string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode, body)
	}
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
	server := formServer(t, repo, siteID(repo.site.State()), board)
	defer server.Close()
	server.Config.Handler = repo.trafficHandler(repo.wafHandler(server.Config.Handler), false)
	for i, text := range []string{"https://example.test/p", "https://example。test/p", "https://%65xample.test/p", `https:\\example.test\p`, "https://unrelated.test/p"} {
		fields := url.Values{"bbs": {"news"}, "subject": {fmt.Sprintf("URL検査%d", i)}, "MESSAGE": {text}, "oimo_request_id": {fmt.Sprintf("domain-security-%04d", i)}}
		result, err := sendForm(server, fields)
		if err != nil || result.Accepted != (i == 4) {
			t.Fatalf("domain bypass: %q accepted=%t err=%v", text, result.Accepted, err)
		}
		g := &abuseGuard{}
		rule := GlobalPostingRule{ID: domain.NewID(), Field: "domain", Operator: "suffix", Value: "example.test", Operation: "both", Mode: "reject", Starts: 1, Enabled: true}
		g.globalRules = &globalRuleSet{rules: []compiledGlobalRule{{rule: rule, condition: compiledRuleCondition{condition: denialCondition{"domain", "suffix", "example.test", "deny"}}}}}
		err = g.checkGlobalRules(guardEntry{body: text, at: domain.Time(time.Now().UnixNano())})
		if (err == nil) != (i == 4) {
			t.Fatal("global domain boundary", text, err)
		}
	}
}
