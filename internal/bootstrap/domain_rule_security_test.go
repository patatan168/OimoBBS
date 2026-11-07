// URLの宛先表記による投稿規制の迂回を、WAF有効のHTTP投稿と共通規制で検査する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
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

// TestDomainRuleRenderedLinkBoundaries は本文の装飾文字や日本語説明の手前でリンク化される宛先も照合する。
func TestDomainRuleRenderedLinkBoundaries(t *testing.T) {
	for _, separator := range []string{"「", "」", "『", "』", "【", "】", "〈", "〉", "《", "》", "（", "）", "、", "。", "！", "？", "\u00a0", "\u1680", "\u2000", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000", "\ufeff"} {
		body := "https://example.test" + separator + "案内"
		if hosts := postingURLHosts(body); !slices.Contains(hosts, "example.test") {
			t.Errorf("rendered URL escaped domain extraction: body=%q hosts=%q", body, hosts)
		}
	}
	for _, body := range []string{"https://unrelated.test「https://example.test」", "https://unrelated.test。案内 https://example.test！説明", "https://example.test:", "https://example.test/「説明」"} {
		if hosts := postingURLHosts(body); !slices.Contains(hosts, "example.test") {
			t.Errorf("rendered URL escaped domain extraction: body=%q hosts=%q", body, hosts)
		}
	}
}

// TestDomainRuleRenderedLinksHTTP は既存の投稿・管理API fixtureで、各入力の拒否と無関係なURLの受理を比較する。
func TestDomainRuleRenderedLinksHTTP(t *testing.T) {
	t.Run("board", func(t *testing.T) { testRenderedDomainHTTP(t, false) })
	t.Run("global", func(t *testing.T) { testRenderedDomainHTTP(t, true) })
}

// testRenderedDomainHTTP は板別・全板の実APIで同じ規制を保存し、同じ投稿の対照試験を実行する。
func testRenderedDomainHTTP(t *testing.T, global bool) {
	t.Helper()
	for _, body := range []string{"https://example.test「案内」", "https://example.test\u00a0案内", "https://unrelated.test「https://example.test」"} {
		t.Run(body, func(t *testing.T) {
			_, repo, board := anonymousAdminFixture(t, "required")
			defer repo.Close()
			c := newAdminClient(t, repo)
			defer c.server.Close()
			if c.login(adminTestSecret) != 303 {
				t.Fatal("login")
			}
			repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
			server := formServer(t, repo, siteID(repo.site.State()), board)
			defer server.Close()
			server.Config.Handler = repo.trafficHandler(repo.wafHandler(server.Config.Handler), false)
			first, err := sendForm(server, url.Values{"bbs": {"news"}, "subject": {"正常対照"}, "MESSAGE": {body}, "oimo_request_id": {"domain-unrestricted-control"}})
			if err != nil || !first.Accepted {
				t.Fatal("unrestricted control", first.Accepted, err)
			}
			installRenderedDomainRule(t, c, board, global)
			fields := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {body}, "oimo_request_id": {"domain-restricted-reply"}}
			result, err := sendForm(server, fields)
			if err != nil || result.Accepted {
				t.Error("rendered domain bypass", result.Accepted, err)
			}
			fields.Set("MESSAGE", "https://unrelated.test/ 許可対照")
			fields.Set("oimo_request_id", "domain-unrelated-reply")
			result, err = sendForm(server, fields)
			if err != nil || !result.Accepted {
				t.Fatal("unrelated control", result.Accepted, err)
			}
		})
	}
}

// installRenderedDomainRule は既存のテストと同じ認証・再認証・CSRF・CASの手順で規制を保存する。
func installRenderedDomainRule(t *testing.T, c *adminClient, board domain.ID, global bool) {
	t.Helper()
	if global {
		postGlobalEdit(t, c, globalRuleEdit{Action: "add", Field: "domain", Operator: "suffix", Value: "example.test", Operation: "both", Mode: "reject", Minutes: 60})
		return
	}
	res, _ := c.rules(board)
	input := AdminRuleInput{Target: "example.test", Operations: []string{"create", "reply"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{"domain", "suffix", "deny"}}
	raw, _ := json.Marshal(input)
	res, response := c.request("POST", "/api/v1/boards/"+board.String()+"/rules", string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode, response)
	}
}

// TestDomainRuleBrowser は実際のリンク先と、同じ本文を規制後に投稿した結果をChromiumで確認する。
func TestDomainRuleBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-domain-rule-browser.mjs")
}
