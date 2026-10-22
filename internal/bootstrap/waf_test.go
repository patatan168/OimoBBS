// WAFの管理フォーム・再認証・即時反映・再送・再起動を実HTTPで検証する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"regexp"
	"strings"
	"testing"
	"time"
)

// wafPublicServer は実サーバーと同じ要求ハンドラーと接続観測をloopbackで起動する。
func wafPublicServer(t *testing.T, repo *Repository) *httptest.Server {
	t.Helper()
	configured, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(configured.Handler)
	server.Config.ConnContext = configured.ConnContext
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func TestWAFHTTPPersistenceAndToggle(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	_, err := repo.CreateBoard(t.Context(), "news", "WAF試験")
	if err != nil {
		t.Fatal(err)
	}
	public := wafPublicServer(t, repo)
	request := func(server *httptest.Server, path string) int {
		t.Helper()
		req, _ := http.NewRequest("GET", server.URL+path, nil)
		req.Host = "127.0.0.1:9080"
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	if status := request(public, "/.git/config"); status == 403 {
		t.Fatal("WAF enabled by default")
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if response, _ := client.request("GET", "/api/v1/waf", "", nil); response.StatusCode != 401 {
		t.Fatal("anonymous access")
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page := client.request("GET", "/waf", "", nil)
	fields := wafPageFields(page)
	fields.Set("enabled", "true")
	fields.Set("traffic_enabled", "true")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	response, _ := client.request("POST", "/waf", fields.Encode(), headers)
	if response.StatusCode != 403 || repo.wafSettings().Enabled {
		t.Fatal("missing reauthentication accepted", response.StatusCode)
	}
	if client.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	_, page = client.request("GET", "/waf", "", nil)
	fields = wafPageFields(page)
	fields.Set("enabled", "true")
	fields.Set("client_enabled", "false")
	fields.Set("client_rate", "45")
	fields.Set("client_burst", "160")
	fields.Set("posting_global_rate", "200")
	fields.Set("posting_global_burst", "400")
	fields.Set("posting_global_concurrent", "64")
	fields.Set("traffic_enabled", "true")
	bad := url.Values{}
	for key, values := range fields {
		bad[key] = append([]string{}, values...)
	}
	bad.Set("csrf", "invalid")
	if response, _ = client.request("POST", "/waf", bad.Encode(), headers); response.StatusCode != 403 {
		t.Fatal("CSRF bypass")
	}
	response, body := client.request("POST", "/waf", fields.Encode(), headers)
	if response.StatusCode != 303 || !repo.wafSettings().Enabled {
		t.Fatal(response.StatusCode, body)
	}
	if response, _ = client.request("POST", "/waf", fields.Encode(), headers); response.StatusCode != 303 {
		t.Fatal("idempotent retry", response.StatusCode)
	}
	fields.Set("enabled", "false")
	if response, _ = client.request("POST", "/waf", fields.Encode(), headers); response.StatusCode != 409 {
		t.Fatal("request key reused", response.StatusCode)
	}
	fields.Set("enabled", "true")
	fields.Set("traffic_enabled", "true")
	fields.Set("request_id", domain.NewID().String())
	if response, _ = client.request("POST", "/waf", fields.Encode(), headers); response.StatusCode != 412 {
		t.Fatal("stale save", response.StatusCode)
	}
	if status := request(public, "/.git/config"); status != 403 || repo.wafBlocked.Load() != 1 {
		t.Fatal("live WAF", status, repo.wafBlocked.Load())
	}
	if status := request(public, "/news/subject.txt"); status != 200 {
		t.Fatal("normal traffic", status)
	}
	state := repo.site.State()
	var site siteState
	if err = strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil || site.MinimumReader != max(wafReader, postingResourcesReader, specialNetworkReader, dnsDisplayReader) {
		t.Fatal(site.MinimumReader, err)
	}
	site.MinimumReader = wafReader - 1
	row := state.Rows["site:state"]
	row.Value, _ = json.Marshal(site)
	state.Rows["site:state"] = row
	if _, err = inspectSiteState(state, site.ID, cfg.Public.BaseURL); err == nil {
		t.Fatal("old reader accepted WAF")
	}
	public.Close()
	client.server.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if repo.wafSettings().Traffic.ClientEnabled {
		t.Fatal("network OFF was not retained")
	}
	if !repo.wafSettings().Enabled || repo.wafSettings().Traffic.ClientRate != 45 || repo.wafSettings().Traffic.ClientBurst != 160 || repo.wafSettings().Traffic.Posting.GlobalRate != 200 || repo.wafSettings().Traffic.Posting.GlobalBurst != 400 || repo.wafSettings().Traffic.Posting.GlobalConcurrent != 64 || repo.wafBlocked.Load() != 0 {
		t.Fatal("persistence or process counter")
	}
	public = wafPublicServer(t, repo)
	if status := request(public, "/.git/config"); status != 403 {
		t.Fatal("WAF lost after restart")
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("relogin")
	}
	response, body = client.request("GET", "/api/v1/waf", "", nil)
	apiHeaders := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {response.Header.Get("X-CSRF-Token")}, "If-Match": {response.Header.Get("ETag")}, "Idempotency-Key": {domain.NewID().String()}}
	response, body = client.request("POST", "/api/v1/waf", `{"enabled":false}`, apiHeaders)
	if response.StatusCode != 200 || repo.wafSettings().Enabled || repo.wafSettings().Traffic.ClientEnabled || repo.wafSettings().Traffic.ClientRate != 45 || repo.wafSettings().Traffic.Posting.GlobalRate != 200 {
		t.Fatal("disable API", response.StatusCode, body)
	}
	if status := request(public, "/.git/config"); status == 403 {
		t.Fatal("WAF remained active")
	}
	// OFFも保存し、保存形式は対応readerを要求し続ける。
	public.Close()
	client.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if repo.wafSettings().Enabled {
		t.Fatal("OFF not durable")
	}
}

func TestWAFPermissionAndStrictInput(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	info, err := repo.CreateBoard(t.Context(), "scope", "担当板")
	if err != nil {
		t.Fatal(err)
	}
	account, err := repo.CreateAdministrator("limited", "担当者", adminTestSecret, AdministratorAccess{Role: "board_admin", Boards: []domain.ID{info.ID}, Permissions: []string{}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	cookie, session, err := repo.adminAuth.Create(account.ID, account.Generation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.updateWAF(session, WAFSettings{Enabled: true, Traffic: repo.wafSettings().Traffic}, `"waf:0"`, domain.NewID().String()); err == nil {
		t.Fatal("limited account toggled WAF")
	}
	client.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: cookie}
	for _, path := range []string{"/waf", "/api/v1/waf"} {
		if response, _ := client.request("GET", path, "", nil); response.StatusCode != 403 {
			t.Fatal("limited GET", path, response.StatusCode)
		}
		if response, _ := client.request("POST", path, `{"enabled":true}`, http.Header{"Content-Type": {"application/json"}}); response.StatusCode != 403 {
			t.Fatal("limited POST", path, response.StatusCode)
		}
	}
	for _, raw := range []string{`{}`, `{"enabled":null}`, `{"enabled":"true"}`, `{"enabled":true,"extra":1}`, `{"enabled":true,"enabled":false}`} {
		if validateWAFValue("active", []byte(raw)) == nil {
			t.Fatal("invalid setting accepted", raw)
		}
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	response, page := client.request("GET", "/waf", "", nil)
	if response.StatusCode != 200 || !strings.Contains(page, `name="enabled"`) {
		t.Fatal("toggle page")
	}
	if response, _ = client.request("GET", "/operations", "", nil); response.StatusCode != 200 {
		t.Fatal("operations link")
	}
}

// wafPageFields は実際に描画された数値入力を含めて通常フォームを再現する。
func wafPageFields(page string) url.Values {
	fields := pageFields(page)
	numbers := regexp.MustCompile(`<input type="number" name="([^"]+)"[^>]* value="([^"]*)">`)
	for _, input := range numbers.FindAllStringSubmatch(page, -1) {
		fields.Set(input[1], input[2])
	}
	selects := regexp.MustCompile(`(?s)<select name="([^"]+)"[^>]*>(.*?)</select>`)
	selected := regexp.MustCompile(`<option value="([^"]+)" selected>`)
	for _, selectField := range selects.FindAllStringSubmatch(page, -1) {
		if option := selected.FindStringSubmatch(selectField[2]); option != nil {
			fields.Set(selectField[1], option[1])
		}
	}
	return fields
}

// WAF画面から通常フォームで再認証した後、その設定画面へ戻れることを確認する。
func TestWAFReauthenticationReturnsToSettings(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	route := "/reauth?return_to=%2Fwaf"
	response, page := client.request("GET", route, "", nil)
	if response.StatusCode != 200 || !strings.Contains(page, `return_to=%2Fwaf`) {
		t.Fatal("return path missing", response.StatusCode)
	}
	fields := pageFields(page)
	fields.Set("password", adminTestSecret)
	response, _ = client.request("POST", route, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 303 || response.Header.Get("Location") != "/waf" {
		t.Fatal("wrong reauthentication destination", response.StatusCode, response.Header.Get("Location"))
	}
}
