// 管理HTTPで規制登録・解除し、実HTTP投稿と再送・再起動・失敗を確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"strings"
	"sync"
	"testing"
	"time"
)

func (c *adminClient) rules(id domain.ID) (*http.Response, AdminRules) {
	c.t.Helper()
	res, body := c.request("GET", "/api/v1/boards/"+id.String()+"/rules", "", nil)
	var v struct {
		Data AdminRules `json:"data"`
	}
	if e := json.Unmarshal([]byte(body), &v); e != nil {
		c.t.Fatal(e)
	}
	return res, v.Data
}
func ruleResponse(t *testing.T, body string) AdminRule {
	t.Helper()
	var v struct {
		Data AdminRule `json:"data"`
	}
	if e := json.Unmarshal([]byte(body), &v); e != nil {
		t.Fatal(e)
	}
	return v.Data
}
func TestAdminRulesPostingRecoveryAndRevoke(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	other, e := repo.CreateBoard(context.Background(), "other", "別板")
	if e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/api/v1/boards/" + info.ID.String() + "/rules"
	res, _ := client.rules(info.ID)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"create-denial-rule-001"}}
	form := formServer(t, repo, siteID(repo.site.State()), info.ID)
	defer func() { form.Close() }()
	create := url.Values{"bbs": {"news"}, "subject": {"first"}, "MESSAGE": {"first"}, "oimo_request_id": {"rules-post-create-0001"}}
	first, e := sendForm(form, create)
	if e != nil || !first.Accepted {
		t.Fatal("initial post", first, e)
	}
	reply := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"second"}, "oimo_request_id": {"rules-post-reply-00001"}}
	pending, e := sendFormOnce(form, reply, "")
	if e != nil || pending.Confirmation == nil {
		t.Fatal("confirmation", e)
	}
	input := AdminRuleInput{"127.0.0.0/8", []string{"reply"}, 60, "spam", nil, nil, nil, nil}
	raw, _ := json.Marshal(input)
	res, body := client.request("POST", path, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("create rule", res.StatusCode, body)
	}
	rule := ruleResponse(t, body)
	if rule.ID == (domain.ID{}) || rule.RevokeCSRF == "" {
		t.Fatal("missing rule/CSRF")
	}
	denied, e := sendFormOnce(form, reply, pending.Confirmation.Token)
	if e != nil || denied.Accepted || denied.Confirmation != nil {
		t.Fatal("confirmed post bypass", denied, e)
	}
	retry, e := sendForm(form, create)
	if e != nil || !retry.Duplicate || retry.Key != first.Key {
		t.Fatal("accepted retry lost", retry, e)
	}
	// replyだけの規制は同じIPのスレ立てへ波及しない。
	create.Set("oimo_request_id", "rules-post-create-0002")
	yes, e := sendForm(form, create)
	if e != nil || !yes.Accepted {
		t.Fatal("create scope", yes, e)
	}
	_, untouched := client.rules(other.ID)
	if len(untouched.Rules) != 0 {
		t.Fatal("other board affected")
	}
	res, body = client.request("POST", path, string(raw), headers)
	duplicate := ruleResponse(t, body)
	if res.StatusCode != 200 || duplicate.ID != rule.ID || duplicate.Expires != rule.Expires {
		t.Fatal("rule duplicated/extended")
	}
	different := input
	different.Minutes = 120
	conflict, _ := json.Marshal(different)
	res, _ = client.request("POST", path, string(conflict), headers)
	if res.StatusCode != 409 {
		t.Fatal("idempotency conflict", res.StatusCode)
	}
	form.Close()
	client.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	form = formServer(t, repo, siteID(repo.site.State()), info.ID)
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	res, list := client.rules(info.ID)
	if len(list.Rules) != 1 || list.Rules[0].ID != rule.ID {
		t.Fatal("rule not durable")
	}
	headers.Set("X-CSRF-Token", res.Header.Get("X-CSRF-Token"))
	res, body = client.request("POST", path, string(raw), headers)
	if res.StatusCode != 200 || ruleResponse(t, body).ID != rule.ID {
		t.Fatal("receipt not durable", res.StatusCode)
	}
	denied, e = sendForm(form, reply)
	if e != nil || denied.Accepted {
		t.Fatal("restart opened rule", e)
	}
	revokeHeaders := http.Header{"Content-Type": {"application/json"}, "If-Match": {rule.ETag()}, "X-Csrf-Token": {list.Rules[0].RevokeCSRF}, "Idempotency-Key": {"revoke-denial-rule-001"}}
	revoke := path + "/" + rule.ID.String() + "/revoke"
	res, body = client.request("POST", revoke, "{}", revokeHeaders)
	removed := ruleResponse(t, body)
	if res.StatusCode != 200 || removed.Enabled || removed.Revision != 2 {
		t.Fatal("revoke", res.StatusCode, body)
	}
	res, _ = client.request("POST", revoke, "{}", revokeHeaders)
	if res.StatusCode != 200 {
		t.Fatal("revoke retry", res.StatusCode)
	}
	yes, e = sendForm(form, reply)
	if e != nil || !yes.Accepted || yes.Number != 2 {
		t.Fatal("revoke not applied", yes, e)
	}
	// 解除後にも作成の元結果を返し、再送で規制を再有効化しない。
	res, body = client.request("POST", path, string(raw), headers)
	if res.StatusCode != 200 || ruleResponse(t, body).ID != rule.ID {
		t.Fatal("old result lost")
	}
	_, list = client.rules(info.ID)
	if list.Rules[0].Enabled {
		t.Fatal("retry reenabled rule")
	}
}

func TestAdminRulesCASFormsAndExpiry(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	path := "/api/v1/boards/" + info.ID.String() + "/rules"
	if res, _ := client.request("GET", path, "", nil); res.StatusCode != 401 {
		t.Fatal("anonymous list")
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := client.rules(info.ID)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"rule-invalid-test-001"}}
	input := AdminRuleInput{"127.0.0.1", []string{"create", "reply"}, 1, "manual", nil, nil, nil, nil}
	raw, _ := json.Marshal(input)
	bad := headers.Clone()
	bad.Set("Origin", "http://attacker.invalid")
	if res, _ := client.request("POST", path, string(raw), bad); res.StatusCode != 403 {
		t.Fatal("origin bypass")
	}
	bad = headers.Clone()
	bad.Set("X-CSRF-Token", "wrong")
	if res, _ := client.request("POST", path, string(raw), bad); res.StatusCode != 403 {
		t.Fatal("csrf bypass")
	}
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := headers.Clone()
			h.Set("Idempotency-Key", fmt.Sprintf("rule-cas-request-%03d", i))
			res, _ := client.request("POST", path, string(raw), h)
			statuses <- res.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for code := range statuses {
		counts[code]++
	}
	if counts[200] != 1 || counts[412] != 1 {
		t.Fatal("CAS", counts)
	}
	action := "/boards/" + info.ID.String() + "/rules"
	_, page := client.request("GET", action, "", nil)
	fields := pageFields(strings.Split(page, "</form>")[0])
	fields.Set("target", "192.0.2.1/24")
	fields.Set("operation", "both")
	fields.Set("field", "auto")
	fields.Set("operator", "exact")
	fields.Set("effect", "deny")
	fields.Set("duration_minutes", "60")
	fields.Set("reason_code", "manual")
	formHeaders := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, page = client.request("POST", action, fields.Encode(), formHeaders)
	if res.StatusCode != 422 || !strings.Contains(page, "192.0.2.1/24") || !strings.Contains(page, fields.Get("request_id")) {
		t.Fatal("invalid form lost", res.StatusCode)
	}
	fields.Set("target", "192.0.2.0/24")
	res, _ = client.request("POST", action, fields.Encode(), formHeaders)
	if res.StatusCode != 303 {
		t.Fatal("HTML create", res.StatusCode)
	}
	res, _ = client.request("POST", action, fields.Encode(), formHeaders)
	if res.StatusCode != 303 {
		t.Fatal("HTML retry")
	}
	fields.Set("request_id", "rule-stale-form-0001")
	res, page = client.request("POST", action, fields.Encode(), formHeaders)
	if res.StatusCode != 412 || !strings.Contains(page, fields.Get("request_id")) {
		t.Fatal("stale form lost")
	}
	// 実際の投稿経路でも有効期限ちょうどから解除する。待機せず板時計を進める。
	_, list := client.rules(info.ID)
	var expiry time.Time
	for _, rule := range list.Rules {
		if rule.Target == "127.0.0.1" {
			expiry, _ = time.Parse(time.RFC3339Nano, rule.Expires)
		}
	}
	b := repo.posting[info.ID]
	if _, e = b.worker.Submit(context.Background(), func() (any, error) { b.clock = func() time.Time { return expiry }; return nil, nil }); e != nil {
		t.Fatal(e)
	}
	server := formServer(t, repo, siteID(repo.site.State()), info.ID)
	defer server.Close()
	result, e := sendForm(server, url.Values{"bbs": {"news"}, "subject": {"expired"}, "MESSAGE": {"post after expiry"}})
	if e != nil || !result.Accepted {
		t.Fatal("expiry blocked posting", result, e)
	}
}

func TestAdminRulesSaveFailure(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	action := "/boards/" + info.ID.String() + "/rules"
	_, page := client.request("GET", action, "", nil)
	fields := pageFields(strings.Split(page, "</form>")[0])
	fields.Set("target", "127.0.0.1")
	fields.Set("operation", "both")
	fields.Set("field", "auto")
	fields.Set("operator", "exact")
	fields.Set("effect", "deny")
	fields.Set("duration_minutes", "60")
	fields.Set("reason_code", "manual")
	if e = repo.boards[info.ID].Close(); e != nil {
		t.Fatal(e)
	}
	res, page := client.request("POST", action, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 503 || res.Header.Get("X-Operation-ID") == "" || !strings.Contains(page, fields.Get("request_id")) {
		t.Fatal("failed save", res.StatusCode)
	}
	client.server.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	res, list := client.rules(info.ID)
	if len(list.Rules) != 0 {
		t.Fatal("failed rule published")
	}
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {fields.Get("revision")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {fields.Get("request_id")}}
	raw, _ := json.Marshal(AdminRuleInput{"127.0.0.1", []string{"create", "reply"}, 60, "manual", nil, nil, nil, nil})
	res, _ = client.request("POST", "/api/v1"+action, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("retry failed", res.StatusCode)
	}
}

// 拒否規制の登録・解除・再起動で、受理済み投稿の600秒作成枠をリセットしない。
func TestAdminRulesPreserveAdmission(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.EnableAdmission(); e != nil {
		t.Fatal(e)
	}
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	form := formServer(t, repo, siteID(repo.site.State()), info.ID)
	defer func() { form.Close() }()
	post := url.Values{"bbs": {"news"}, "subject": {"first"}, "MESSAGE": {"first"}, "oimo_request_id": {"rule-rate-create-0001"}}
	first, e := sendForm(form, post)
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/api/v1/boards/" + info.ID.String() + "/rules"
	res, _ := client.rules(info.ID)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"rule-with-rate-000001"}}
	raw, _ := json.Marshal(AdminRuleInput{"127.0.0.1", []string{"create"}, 60, "manual", nil, nil, nil, nil})
	res, body := client.request("POST", path, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("rule", res.StatusCode)
	}
	rule := ruleResponse(t, body)
	retry, e := sendForm(form, post)
	if e != nil || !retry.Duplicate {
		t.Fatal("retry denied", retry, e)
	}
	headers.Set("If-Match", rule.ETag())
	headers.Set("X-CSRF-Token", rule.RevokeCSRF)
	headers.Set("Idempotency-Key", "revoke-with-rate-0001")
	res, _ = client.request("POST", path+"/"+rule.ID.String()+"/revoke", "{}", headers)
	if res.StatusCode != 200 {
		t.Fatal("revoke", res.StatusCode)
	}
	post.Set("oimo_request_id", "rule-rate-create-0002")
	blocked, e := sendForm(form, post)
	if e != nil || blocked.Accepted {
		t.Fatal("rate reset", blocked, e)
	}
	client.server.Close()
	form.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	form = formServer(t, repo, siteID(repo.site.State()), info.ID)
	blocked, e = sendForm(form, post)
	if e != nil || blocked.Accepted {
		t.Fatal("rate reset on recovery", blocked, e)
	}
	history, e := repo.rateHistory()
	if e != nil || len(history) != 1 {
		t.Fatal("accepted history changed", len(history), e)
	}
}
