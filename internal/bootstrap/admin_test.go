// 管理HTTPの認証・CSRF・CAS・永続再送・公開との分離を実HTTPで確認する。
package bootstrap

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/postcapture"
	"strings"
	"sync"
	"testing"
)

const adminTestSecret = "testing-admin-password-keep-private"

// TestAdministratorBrowserFormOriginPolicy はブラウザの管理フォーム送信を維持し、null/外部Originを拒否する。
func TestAdministratorBrowserFormOriginPolicy(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	res, page := c.request("GET", "/login", "", nil)
	if res.StatusCode != 200 || res.Header.Get("Referrer-Policy") != "same-origin" {
		t.Fatal("browser form requires same-origin referrer policy")
	}
	fields := pageFields(page)
	fields.Set("login", "owner")
	fields.Set("password", adminTestSecret)
	for _, origin := range []string{"null", "https://example.com"} {
		res, _ = c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {origin}, "Sec-Fetch-Site": {"same-origin"}})
		if res.StatusCode != 403 {
			t.Fatal("untrusted origin accepted", origin, res.StatusCode)
		}
	}
	res, _ = c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Sec-Fetch-Site": {"same-origin"}})
	if res.StatusCode != 303 {
		t.Fatal("same-origin browser form rejected", res.StatusCode)
	}
}

func adminFixture(t *testing.T) (Config, *Repository) {
	t.Helper()
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "管理前"); e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ConfigureAdministrator("owner", "所有者", adminTestSecret, false); e != nil {
		repo.Close()
		t.Fatal(e)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	return cfg, repo
}

type adminClient struct {
	t       *testing.T
	server  *httptest.Server
	cookies map[string]*http.Cookie
	origin  string
}

func newAdminClient(t *testing.T, repo *Repository) *adminClient {
	t.Helper()
	server, e := repo.AdminHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewServer(server.Handler)
	s.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &adminClient{t, s, map[string]*http.Cookie{}, repo.cfg.Admin.Origin}
}
func (c *adminClient) request(method, path, body string, headers http.Header) (*http.Response, string) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.server.URL+path, strings.NewReader(body))
	u, _ := url.Parse(c.origin)
	req.Host = u.Host
	if method != "GET" {
		req.Header.Set("Origin", c.origin)
	}
	if headers != nil {
		for name, values := range headers {
			req.Header[name] = append([]string{}, values...)
		}
	}
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}
	res, e := c.server.Client().Do(req)
	if e != nil {
		c.t.Fatal(e)
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(res.Body)
	if e != nil {
		c.t.Fatal(e)
	}
	for _, cookie := range res.Cookies() {
		if cookie.MaxAge < 0 {
			delete(c.cookies, cookie.Name)
		} else {
			c.cookies[cookie.Name] = cookie
		}
	}
	cache := "no-store"
	if res.Header.Get("Cache-Control") != cache {
		c.t.Fatal("unexpected admin cache policy")
	}
	if strings.Contains(string(raw), adminTestSecret) || strings.Contains(string(raw), "digest_base64") {
		c.t.Fatal("credential exposed")
	}
	return res, string(raw)
}
func (c *adminClient) login(secret string) int {
	c.t.Helper()
	_, page := c.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", "owner")
	fields.Set("password", secret)
	res, _ := c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	return res.StatusCode
}
func (c *adminClient) site() (*http.Response, AdminSite) {
	c.t.Helper()
	res, body := c.request("GET", "/api/v1/site", "", nil)
	var v struct {
		Data AdminSite `json:"data"`
	}
	if e := json.Unmarshal([]byte(body), &v); e != nil {
		c.t.Fatal(e)
	}
	return res, v.Data
}
func TestAdminHTTPPersistenceAndIsolation(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	res, _ := client.request("GET", "/api/v1/site", "", nil)
	if res.StatusCode != 401 {
		t.Fatal("anonymous settings")
	}
	if status := client.login("wrong password value"); status != 401 {
		t.Fatal("wrong login", status)
	}
	if status := client.login(adminTestSecret); status != 303 {
		t.Fatal("login", status)
	}
	cookie := *client.cookies["oimo_admin"]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatal("session cookie flags")
	}
	res, site := client.site()
	if res.StatusCode != 200 || site.Name != "管理前" {
		t.Fatal("settings")
	}
	etag, csrf := res.Header.Get("ETag"), res.Header.Get("X-CSRF-Token")
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {etag}, "Idempotency-Key": {"admin-update-test-0001"}, "X-Csrf-Token": {csrf}}
	bad := headers.Clone()
	bad.Set("Origin", "http://attacker.invalid")
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"拒否"}`, bad)
	if res.StatusCode != 403 {
		t.Fatal("origin bypass")
	}
	bad = headers.Clone()
	bad.Set("X-CSRF-Token", "bad")
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"拒否"}`, bad)
	if res.StatusCode != 403 {
		t.Fatal("csrf bypass")
	}
	bad = headers.Clone()
	bad.Del("If-Match")
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"拒否"}`, bad)
	if res.StatusCode != 428 {
		t.Fatal("missing revision", res.StatusCode)
	}
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"a","name":"b"}`, headers)
	if res.StatusCode != 400 {
		t.Fatal("duplicate JSON")
	}
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"管理済み<script>"}`, headers)
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode)
	}
	savedETag := res.Header.Get("ETag")
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"管理済み<script>"}`, headers)
	if res.StatusCode != 200 || res.Header.Get("ETag") != savedETag {
		t.Fatal("duplicate changed revision")
	}
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"別内容"}`, headers)
	if res.StatusCode != 409 {
		t.Fatal("key conflict", res.StatusCode)
	}
	bad = headers.Clone()
	bad.Set("Idempotency-Key", "admin-update-test-0002")
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"古い画面"}`, bad)
	if res.StatusCode != 412 {
		t.Fatal("stale revision")
	}
	// 管理ルートは公開ハンドラに存在せず、公開一覧は設定変更を反映する。
	public, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/api/v1/site", "/login"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", cfg.Public.BaseURL+path, nil)
		public.Handler.ServeHTTP(w, req)
		if w.Code != 404 {
			t.Fatal("public admin route", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+"/", nil))
	if !strings.Contains(w.Body.String(), "管理済み&lt;script&gt;") {
		t.Fatal("public setting not reflected")
	}
	// 保存先を開き直しても同じ要求は元結果。旧sessionは無効。
	client.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	client = newAdminClient(t, repo)
	client.cookies["oimo_admin"] = &cookie
	res, _ = client.request("GET", "/api/v1/site", "", nil)
	if res.StatusCode != 401 {
		t.Fatal("session survived restart")
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	res, _ = client.site()
	headers.Set("X-CSRF-Token", res.Header.Get("X-CSRF-Token"))
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"管理済み<script>"}`, headers)
	if res.StatusCode != 200 || res.Header.Get("ETag") != savedETag {
		t.Fatal("receipt not durable", res.StatusCode, res.Header.Get("ETag"), savedETag)
	}
	// logout後にCookie原文を戻しても再認証できない。
	old := *client.cookies["oimo_admin"]
	_, page := client.request("GET", "/", "", nil)
	csrf = pageFields(page).Get("csrf")
	res, _ = client.request("POST", "/logout", url.Values{"csrf": {csrf}}.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("logout")
	}
	client.cookies["oimo_admin"] = &old
	res, _ = client.request("GET", "/api/v1/site", "", nil)
	if res.StatusCode != 401 {
		t.Fatal("logout cookie reused")
	}
}
func TestAdminConcurrentCASAndHTML(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := client.site()
	etag, csrf := res.Header.Get("ETag"), res.Header.Get("X-CSRF-Token")
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for _, name := range []string{"first", "second"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {etag}, "X-Csrf-Token": {csrf}, "Idempotency-Key": {"concurrent-update-" + name}}
			res, _ := client.request("PATCH", "/api/v1/site", `{"name":"`+name+`"}`, headers)
			statuses <- res.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[200] != 1 || counts[412] != 1 {
		t.Fatal("CAS", counts)
	}
	_, page := client.request("GET", "/", "", nil)
	fields := pageFields(strings.Split(page, "</form>")[0])
	fields.Set("name", "画面から更新")
	formHeaders := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, _ = client.request("POST", "/site", fields.Encode(), formHeaders)
	if res.StatusCode != 303 {
		t.Fatal("HTML save", res.StatusCode)
	}
	res, _ = client.request("POST", "/site", fields.Encode(), formHeaders)
	if res.StatusCode != 303 {
		t.Fatal("HTML retry")
	}
	fields.Set("request_id", "html-stale-request-0001")
	fields.Set("name", "入力を保持")
	res, page = client.request("POST", "/site", fields.Encode(), formHeaders)
	if res.StatusCode != 412 || !strings.Contains(page, "入力を保持") || !strings.Contains(page, "html-stale-request-0001") {
		t.Fatal("HTML conflict input lost")
	}
}

// 管理者を先に作っても規制の有効化でreader版が後退せず、秘密更新は旧認証を拒否する。
func TestAdminResetAndFeatureMigration(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	reopen := func() {
		t.Helper()
		if e := repo.Close(); e != nil {
			t.Fatal(e)
		}
		var e error
		repo, e = OpenPostingRepository(cfg, postcapture.Validate)
		if e != nil {
			t.Fatal(e)
		}
	}
	if _, e := repo.EnableAdmission(); e != nil {
		t.Fatal(e)
	}
	reopen()
	if _, e := repo.EnableAnonymous("required"); e != nil {
		t.Fatal(e)
	}
	reopen()
	client := newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("initial login")
	}
	old := *client.cookies["oimo_admin"]
	client.server.Close()
	info, e := repo.ConfigureAdministrator("owner", "所有者", "replacement-admin-password", true)
	if e != nil || info.Generation != 2 {
		t.Fatal("reset", info, e)
	}
	reopen()
	client = newAdminClient(t, repo)
	defer client.server.Close()
	client.cookies["oimo_admin"] = &old
	if res, _ := client.request("GET", "/api/v1/site", "", nil); res.StatusCode != 401 {
		t.Fatal("old session accepted")
	}
	if client.login(adminTestSecret) != 401 {
		t.Fatal("old password accepted")
	}
	if client.login("replacement-admin-password") != 303 {
		t.Fatal("new password rejected")
	}
}

func TestAdminLoginBoundaryAndSaveFailure(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	_, page := client.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", "owner")
	fields.Set("password", adminTestSecret)
	fields.Set("csrf", "invalid")
	if res, _ := client.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}); res.StatusCode != 403 {
		t.Fatal("login CSRF accepted")
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	// 認証があっても外部接続元とHost違いを拒否する。
	server, e := repo.AdminHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	for _, external := range []bool{false, true} {
		req := httptest.NewRequest("GET", client.origin+"/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		if external {
			req.RemoteAddr = "192.0.2.1:12345"
		} else {
			req.Host = "attacker.invalid"
		}
		req.AddCookie(client.cookies["oimo_admin"])
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatal("listener boundary bypass", w.Code)
		}
	}
	_, page = client.request("GET", "/", "", nil)
	fields = pageFields(strings.Split(page, "</form>")[0])
	fields.Set("name", "保存結果不明")
	if e = repo.site.Close(); e != nil {
		t.Fatal(e)
	}
	res, page := client.request("POST", "/site", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 503 || res.Header.Get("X-Operation-ID") == "" || !strings.Contains(page, fields.Get("request_id")) || !strings.Contains(page, "保存結果不明") {
		t.Fatal("save failure not preserved", res.StatusCode)
	}
}
