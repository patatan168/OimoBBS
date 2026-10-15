// 稼働中の個別・全体失効、再認証・CSRF・CAS・固定receiptと再起動を実HTTPで検査する。
package bootstrap

import (
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

func (c *adminClient) anonymous() (*http.Response, AdminAnonymous) {
	res, body := c.request("GET", "/api/v1/anonymous", "", nil)
	var reply struct {
		Data AdminAnonymous `json:"data"`
	}
	if e := json.Unmarshal([]byte(body), &reply); e != nil {
		c.t.Fatal(e)
	}
	return res, reply.Data
}
func (c *adminClient) reauthAnonymous() {
	res, _ := c.request("GET", "/api/v1/reauth", "", nil)
	raw, _ := json.Marshal(map[string]string{"password": adminTestSecret})
	res, body := c.request("POST", "/api/v1/reauth", string(raw), http.Header{"Content-Type": {"application/json"}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}})
	if res.StatusCode != 200 {
		c.t.Fatal("reauth", res.StatusCode, body)
	}
}
func TestAdminAnonymousOnlineAndRecovery(t *testing.T) {
	cfg, repo, board := anonymousAdminFixture(t, "required")
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	server, request, cookies := anonymousHTTP(t, repo, siteID(repo.site.State()))
	defer server.Close()
	fields := url.Values{"bbs": {"news"}, "subject": {"失効試験"}, "MESSAGE": {"本文"}, "oimo_request_id": {"online-anonymous-post-01"}}
	request("POST", "/test/bbs.cgi", fields)
	tokenCookie := cookies["oimo_anon"]
	token, e := repo.anonymous.verify(tokenCookie.Value, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	request("POST", "/test/bbs.cgi", fields)
	var thread uint64
	for key := range repo.posting[board].threads {
		thread = key
	}
	reply := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(thread)}, "MESSAGE": {"旧Cookie"}, "oimo_request_id": {"online-anon-race-001"}}
	res, page := request("POST", "/test/bbs.cgi", reply)
	if res.StatusCode != 200 || !strings.Contains(page, "2ch_X:cookie") {
		t.Fatal("reply confirmation", res.StatusCode, page)
	}
	confirmedReply := cookies["oimo_confirm"]
	subject := repo.anonymous.subject(token.ID)
	res, view := c.anonymous()
	input := anonymousAdminInput{Subject: &subject}
	raw, _ := json.Marshal(input)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {view.ETag()}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"online-anon-revoke-001"}}
	res, _ = c.request("POST", "/api/v1/anonymous", string(raw), headers)
	if res.StatusCode != 403 {
		t.Fatal("reauth bypass", res.StatusCode)
	}
	c.reauthAnonymous()
	res, _ = c.anonymous()
	headers.Set("X-CSRF-Token", res.Header.Get("X-CSRF-Token"))
	bad := headers.Clone()
	bad.Set("X-CSRF-Token", "wrong")
	if res, _ := c.request("POST", "/api/v1/anonymous", string(raw), bad); res.StatusCode != 403 {
		t.Fatal("CSRF bypass")
	}
	res, body := c.request("POST", "/api/v1/anonymous", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("revoke", res.StatusCode, body)
	}
	if repo.stopped || repo.posting[board].stopped {
		t.Fatal("online revoke stopped service")
	}
	if _, e := repo.liveAnonymous.Load().verify(tokenCookie.Value, time.Now()); e == nil {
		t.Fatal("revoked token still valid")
	}
	// 失効完了後に並行で戻した旧Cookieは新しい受理へ使えない。確認応答の発行も固定IP上限内。
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := reply
			// request helperのCookie mapは更新するため並行では使わない。
			r, _ := http.NewRequest("POST", server.URL+"/test/bbs.cgi", strings.NewReader(req.Encode()))
			r.Host = "127.0.0.1:9080"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			r.AddCookie(tokenCookie)
			r.AddCookie(confirmedReply)
			resp, e := server.Client().Do(r)
			if e != nil {
				t.Error(e)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	rows, e := repo.rateHistory()
	if e != nil || len(rows) != 1 {
		t.Fatal("revoked acceptance", len(rows), e)
	}
	res, _ = c.request("POST", "/api/v1/anonymous", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("receipt retry", res.StatusCode)
	}
	// 同じ要求IDで全体失効へ変更することを拒否する。
	res, _ = c.request("POST", "/api/v1/anonymous", `{"subject_hmac":null}`, headers)
	if res.StatusCode != 409 {
		t.Fatal("key conflict", res.StatusCode)
	}
	res, view = c.anonymous()
	headers = http.Header{"Content-Type": {"application/json"}, "If-Match": {view.ETag()}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"online-anon-all-00001"}}
	res, body = c.request("POST", "/api/v1/anonymous", `{"subject_hmac":null}`, headers)
	if res.StatusCode != 200 {
		t.Fatal("revoke all", res.StatusCode, body)
	}
	_, after := c.anonymous()
	if after.Generation != view.Generation+1 {
		t.Fatal("generation did not advance")
	}
	res, _ = c.request("POST", "/api/v1/anonymous", `{"subject_hmac":null}`, headers)
	if res.StatusCode != 200 {
		t.Fatal("revoke all retry")
	}
	_, again := c.anonymous()
	if again.Generation != after.Generation {
		t.Fatal("retry advanced generation")
	}
	c.server.Close()
	server.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("recovery", e)
	}
	if repo.anonymous.policy.Generation != after.Generation || len(repo.anonymous.revoked) != 1 {
		t.Fatal("revocation lost")
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	c.reauthAnonymous()
	res, _ = c.anonymous()
	headers.Set("X-CSRF-Token", res.Header.Get("X-CSRF-Token"))
	res, _ = c.request("POST", "/api/v1/anonymous", `{"subject_hmac":null}`, headers)
	if res.StatusCode != 200 {
		t.Fatal("durable receipt", res.StatusCode)
	}
	_, again = c.anonymous()
	if again.Generation != after.Generation {
		t.Fatal("durable retry advanced generation")
	}
	_, page = c.request("GET", "/anonymous", "", nil)
	if !strings.Contains(page, "全Cookie") || strings.Contains(page, tokenCookie.Value) || strings.Contains(page, subject.String()) {
		t.Fatal("anonymous UI secret")
	}
}

func TestAdminAnonymousSaveFailure(t *testing.T) {
	cfg, repo, _ := anonymousAdminFixture(t, "required")
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	c.reauthAnonymous()
	res, view := c.anonymous()
	repo.site.Close()
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {view.ETag()}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"online-anon-failed-001"}}
	res, body := c.request("POST", "/api/v1/anonymous", `{"subject_hmac":null}`, headers)
	if res.StatusCode != 503 || res.Header.Get("X-Operation-ID") == "" || strings.Contains(body, `"generation":"2"`) {
		t.Fatal("failed save success", res.StatusCode, body)
	}
	if repo.liveAnonymous.Load().policy.Generation != 1 {
		t.Fatal("unsaved state exposed")
	}
	c.server.Close()
	repo.Close()
	var e error
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if repo.anonymous.policy.Generation != 1 {
		t.Fatal("failure advanced generation")
	}
}

func TestAnonymousReceiptShape(t *testing.T) {
	if e := validateAnonymousReceipt(domain.Hash{1}.String(), nil, []byte(`{"type":"anonymous_change"}`)); e == nil {
		t.Fatal("incomplete receipt")
	}
}

func TestAdminAnonymousHTMLKeepsRequest(t *testing.T) {
	_, repo, _ := anonymousAdminFixture(t, "required")
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page := c.request("GET", "/anonymous", "", nil)
	fields := pageFields(page)
	fields.Set("operation", "all")
	fields.Set("subject_hmac", "")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, page := c.request("POST", "/anonymous", fields.Encode(), headers)
	if res.StatusCode != 403 || !strings.Contains(page, fields.Get("request_id")) || !strings.Contains(page, "再認証") {
		t.Fatal("reauth request lost", res.StatusCode, page)
	}
	c.reauthAnonymous()
	_, page = c.request("GET", "/anonymous", "", nil)
	fields = pageFields(page)
	fields.Set("operation", "subject")
	fields.Set("subject_hmac", domain.Hash{}.String())
	res, page = c.request("POST", "/anonymous", fields.Encode(), headers)
	if res.StatusCode != 422 || !strings.Contains(page, fields.Get("subject_hmac")) || !strings.Contains(page, fields.Get("request_id")) {
		t.Fatal("invalid subject lost", res.StatusCode, page)
	}
	fields.Set("operation", "all")
	fields.Set("subject_hmac", "")
	res, page = c.request("POST", "/anonymous", fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("HTML revoke", res.StatusCode, page)
	}
	res, _ = c.request("POST", "/anonymous", fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("HTML retry", res.StatusCode)
	}
	_, state := c.anonymous()
	if state.Generation != 2 {
		t.Fatal("HTML duplicate revoke")
	}
}
