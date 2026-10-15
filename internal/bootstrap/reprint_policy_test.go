// 転載設定の保存・確認束縛・専ブラ互換・クローラー拒否・復旧を検証する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
	"strings"
	"testing"
)

func TestReprintPolicyPublicConfirmationRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "protected", "保護板")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "ordinary", "通常板")
	if err != nil {
		t.Fatal(err)
	}
	_ = other
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID, true)
	defer form.Close()
	fields := url.Values{"bbs": {"protected"}, "subject": {"既存スレッド"}, "MESSAGE": {"保存本文"}, "oimo_request_id": {"reprint-existing-post"}}
	posted, err := sendForm(form, fields)
	if err != nil || !posted.Accepted {
		t.Fatal("post", posted, err)
	}
	datPath := fmt.Sprintf("/protected/dat/%d.dat", posted.Key)
	original := publicLocalRules(t, repo, datPath, nil).Body.Bytes()
	reply := url.Values{"bbs": {"protected"}, "key": {fmt.Sprint(posted.Key)}, "MESSAGE": {"確認本文"}, "oimo_request_id": {"reprint-pending-post"}}
	pending, err := sendFormOnce(form, reply, "")
	if err != nil || pending.Confirmation == nil || pending.Confirmation.NoReprint {
		t.Fatal("pending", err)
	}
	api := "/api/v1/boards/" + board.ID.String() + "/settings"
	save := func(value *bool) {
		t.Helper()
		res, row := client.board(board.ID.String())
		row.Settings.NoReprint = value
		raw, _ := json.Marshal(row.Settings)
		headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}}
		saved, body := client.request("PATCH", api, string(raw), headers)
		if saved.StatusCode != 200 {
			t.Fatal("save", saved.StatusCode, body)
		}
	}
	on := true
	save(&on)
	var site siteState
	if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil {
		t.Fatal(err)
	}
	if site.MinimumReader < 75 {
		t.Fatal("reader migration")
	}
	fresh, err := sendFormOnce(form, reply, pending.Confirmation.Token)
	if err != nil || fresh.Accepted || fresh.Confirmation == nil || !fresh.Confirmation.NoReprint {
		t.Fatal("old confirmation accepted", err)
	}
	var confirmationHTML bytes.Buffer
	if err := postingPageTemplate.Execute(&confirmationHTML, postingPage{Confirmation: fresh.Confirmation, Fields: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	for _, notice := range reprintNotice() {
		if !strings.Contains(confirmationHTML.String(), notice.Text) {
			t.Fatal("confirmation notice missing")
		}
	}
	notices := []string{}
	for _, rule := range reprintNotice() {
		notices = append(notices, rule.Text)
	}
	legacy, err := compat.PostResult("confirm", "内容を確認して再送してください。", "", notices...)
	if err != nil {
		t.Fatal(err)
	}
	legacyText, err := textcodec.Decode(legacy)
	if err != nil || !strings.Contains(legacyText, "<!-- 2ch_X:cookie -->") {
		t.Fatal("legacy marker", err)
	}
	for _, notice := range notices {
		if !strings.Contains(legacyText, notice) {
			t.Fatal("legacy notice")
		}
	}
	if !strings.Contains(confirmationHTML.String(), "案内に同意して書き込む") {
		t.Fatal("confirmation button")
	}
	assertReprintConfirmationHTTP(t, repo, posted.Key)
	// 旧APIの項目省略はONを保持する。
	save(nil)
	if !repo.posting[board.ID].noReprint.Load() {
		t.Fatal("legacy update reset")
	}
	customAPI := "/api/v1/boards/" + board.ID.String() + "/local-rules"
	res, _ := client.request("GET", customAPI, "", nil)
	res, body := client.request("PATCH", customAPI, `{"rules":[{"kind":"paragraph","text":"独自ルール"}]}`, http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal("custom rules", res.StatusCode, body)
	}
	for _, path := range []string{"/protected/", "/protected/index.html", "/protected/subback.html", "/protected/head.txt"} {
		rec := publicLocalRules(t, repo, path, nil)
		text := rec.Body.String()
		if strings.HasSuffix(path, "head.txt") {
			text, err = textcodec.Decode(rec.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
		}
		if rec.Code != 200 || strings.Index(text, "【無断転載禁止】") < 0 || strings.Index(text, "【無断転載禁止】") > strings.Index(text, "独自ルール") {
			t.Fatal("rules ordering", path, rec.Code)
		}
	}
	paths := []string{datPath, "/protected/", "/protected/index.html", "/protected/subback.html", "/protected/subject.txt", "/protected/SETTING.TXT", "/protected/head.txt", fmt.Sprintf("/test/read.cgi/protected/%d/", posted.Key), "/web/post?bbs=protected", "/search", "/test/bbs.cgi"}
	for _, path := range paths {
		blocked := publicLocalRules(t, repo, path, http.Header{"User-Agent": {"Mozilla/5.0 Googlebot/2.1"}, "Range": {"bytes=1-"}})
		if blocked.Code != 403 || !strings.Contains(blocked.Header().Get("X-Robots-Tag"), "noindex") || strings.Contains(blocked.Body.String(), "保存本文") {
			t.Fatal("bot", path, blocked.Code)
		}
	}
	ordinary := publicLocalRules(t, repo, "/ordinary/", http.Header{"User-Agent": {"bingbot"}})
	if ordinary.Code != 200 || ordinary.Header().Get("X-Robots-Tag") != "" {
		t.Fatal("unprotected board blocked")
	}
	get := publicLocalRules(t, repo, datPath, http.Header{"User-Agent": {"OleBoardBrowser/1.0"}, "Accept-Encoding": {"identity"}})
	if get.Code != 200 || !bytes.Equal(get.Body.Bytes(), original) || !strings.Contains(get.Header().Get("Cache-Control"), "private") || !strings.Contains(strings.Join(get.Header().Values("Vary"), ","), "User-Agent") {
		t.Fatal("dedicated feed changed", get.Code, get.Header())
	}
	compressed := publicLocalRules(t, repo, datPath, http.Header{"Accept-Encoding": {"gzip,identity;q=0"}})
	reader, err := compressedFeedReader("gzip", compressed.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	inflated, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || compressed.Code != 200 || !bytes.Equal(inflated, original) || !strings.Contains(strings.Join(compressed.Header().Values("Vary"), ","), "Accept-Encoding") {
		t.Fatal("compressed feed", err)
	}
	cached := publicLocalRules(t, repo, datPath, http.Header{"If-None-Match": {get.Header().Get("ETag")}})
	ranged := publicLocalRules(t, repo, datPath, http.Header{"Range": {"bytes=1-"}})
	if cached.Code != 304 || ranged.Code != 206 || !bytes.Equal(ranged.Body.Bytes(), original[1:]) {
		t.Fatal("cache/range", cached.Code, ranged.Code)
	}
	for _, ua := range []string{"OleBoardBrowser/1.0", "bingbot"} {
		req := httptest.NewRequest("HEAD", cfg.Public.BaseURL+datPath, nil)
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		repo.SiteWebHandler(nil).ServeHTTP(rec, req)
		want := 200
		if ua == "bingbot" {
			want = 403
		}
		if rec.Code != want || rec.Body.Len() != 0 {
			t.Fatal("HEAD", ua, rec.Code)
		}
	}
	robots := publicLocalRules(t, repo, "/robots.txt", nil)
	if robots.Code != 200 || !strings.Contains(robots.Body.String(), "Disallow: /protected/") || strings.Contains(robots.Body.String(), "/ordinary/") {
		t.Fatal("robots scope")
	}
	res, body = client.request("GET", "/boards/"+board.ID.String()+"/settings", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `name="no_reprint"`) || !strings.Contains(body, "無断転載禁止") {
		t.Fatal("admin UI")
	}
	form.Close()
	client.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("reopen", err)
	}
	if !repo.posting[board.ID].noReprint.Load() {
		t.Fatal("cache recovery")
	}
	if publicLocalRules(t, repo, datPath, http.Header{"User-Agent": {"bingbot"}}).Code != 403 {
		t.Fatal("bot recovery")
	}
	client = newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	off := false
	save(&off)
	if publicLocalRules(t, repo, datPath, http.Header{"User-Agent": {"bingbot"}}).Code != 200 {
		t.Fatal("OFF bot")
	}
	head := publicLocalRules(t, repo, "/protected/head.txt", nil)
	text, _ := textcodec.Decode(head.Body.Bytes())
	if strings.Contains(text, "無断転載禁止") || !strings.Contains(text, "独自ルール") {
		t.Fatal("OFF custom rules")
	}
	if strings.Contains(publicLocalRules(t, repo, "/robots.txt", nil).Body.String(), "Disallow:") {
		t.Fatal("OFF robots")
	}
}

func TestReprintPolicyStrictCompatibility(t *testing.T) {
	settings := defaultBoardSettings()
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "no_reprint") {
		t.Fatal("legacy bytes changed")
	}
	var decoded boardSettings
	if strictjson.Decode(raw, &decoded) != nil || decoded.Presentation.reprintDenied() {
		t.Fatal("legacy decode")
	}
	value := true
	settings.Presentation.NoReprint = &value
	raw, _ = json.Marshal(settings)
	if strictjson.Decode(raw, &decoded) != nil || !decoded.Presentation.reprintDenied() {
		t.Fatal("ON decode")
	}
	for _, replacement := range []string{`"no_reprint":"true"`, `"no_reprint":true,"no_reprint":false`, `"unknown":true`} {
		invalid := strings.Replace(string(raw), `"no_reprint":true`, replacement, 1)
		if strictjson.Decode([]byte(invalid), &decoded) == nil {
			t.Fatal("invalid accepted", replacement)
		}
	}
	fields := adminBoardFields(boardEdit(boardValue{Settings: settings}))
	fields.Set("no_reprint", "true")
	edit, err := parseAdminBoardFields(fields)
	if err != nil || edit.NoReprint == nil || !*edit.NoReprint {
		t.Fatal("form parse", err)
	}
	fields.Set("no_reprint", "invalid")
	if _, err := parseAdminBoardFields(fields); err == nil {
		t.Fatal("form invalid")
	}
	key := domain.Hash{1}
	a, _ := confirmationPolicy(key, domain.Versions{}, domain.Policy{}, settings.Input, false)
	b, _ := confirmationPolicy(key, domain.Versions{}, domain.Policy{}, settings.Input, true)
	if a == b {
		t.Fatal("policy not bound")
	}
	if err := validateIdentityReader(siteState{MinimumReader: 74}, boardValue{Settings: settings}); err == nil {
		t.Fatal("reader gate")
	}
}

// assertReprintConfirmationHTTP は実HTTPでWebとlegacyの案内・Cookie発行を確認する。
func assertReprintConfirmationHTTP(t *testing.T, repo *Repository, key uint64) {
	t.Helper()
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "reprint-test")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	base, _ := url.Parse(repo.cfg.Public.BaseURL)
	request := func(method, path string, fields url.Values, cookies []*http.Cookie) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(fields.Encode()))
		req.Host = base.Host
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			req.Header.Set("Origin", repo.cfg.Public.BaseURL)
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res, string(raw)
	}
	path := fmt.Sprintf("/web/post?bbs=protected&key=%d", key)
	form, body := request("GET", path, nil, nil)
	fields := pageFields(body)
	fields.Set("MESSAGE", "HTTP確認本文")
	confirm, body := request("POST", path, fields, form.Cookies())
	if confirm.StatusCode != 200 || !strings.Contains(body, "案内に同意して書き込む") || confirm.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("Web confirmation", confirm.StatusCode)
	}
	for _, rule := range reprintNotice() {
		if !strings.Contains(body, rule.Text) {
			t.Fatal("Web notice missing")
		}
	}
	legacyFields := url.Values{"bbs": {"protected"}, "key": {fmt.Sprint(key)}, "MESSAGE": {"専ブラHTTP確認本文"}, "oimo_request_id": {"reprint-legacy-http"}}
	legacy, body := request("POST", "/test/bbs.cgi", legacyFields, nil)
	decoded, err := textcodec.Decode([]byte(body))
	if err != nil || legacy.StatusCode != 200 || !strings.Contains(decoded, "<!-- 2ch_X:cookie -->") {
		t.Fatal("legacy HTTP", legacy.StatusCode, err)
	}
	for _, rule := range reprintNotice() {
		if !strings.Contains(decoded, rule.Text) {
			t.Fatal("legacy HTTP notice missing")
		}
	}
	found := false
	for _, cookie := range legacy.Cookies() {
		if cookie.Name == "oimo_confirm" {
			found = true
		}
	}
	if !found {
		t.Fatal("legacy cookie missing")
	}
}
