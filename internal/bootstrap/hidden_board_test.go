// 専ブラ閲覧板の一覧表示・検索除外・Web403・専ブラ互換・保存復旧を検証する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
)

func TestHiddenBoardPublicationRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "secretboard", "隠し対象板")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CreateBoard(t.Context(), "visibleboard", "通常板"); err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID, true)
	defer form.Close()
	posted, err := sendForm(form, url.Values{"bbs": {"secretboard"}, "subject": {"秘密タイトル"}, "MESSAGE": {"保存本文"}, "oimo_request_id": {"hidden-existing-post"}})
	if err != nil || !posted.Accepted {
		t.Fatal(posted, err)
	}
	datPath := fmt.Sprintf("/secretboard/dat/%d.dat", posted.Key)
	readPath := fmt.Sprintf("/test/read.cgi/secretboard/%d/l50", posted.Key)
	original := append([]byte{}, publicLocalRules(t, repo, datPath, nil).Body.Bytes()...)
	save := func(value *bool) {
		t.Helper()
		res, row := client.board(board.ID.String())
		row.Settings.Hidden = value
		raw, _ := json.Marshal(row.Settings)
		saved, body := client.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
		if saved.StatusCode != 200 {
			t.Fatal(saved.StatusCode, body)
		}
	}
	on := true
	save(&on)
	save(nil) // 旧APIによる省略は保存済みONを保持する。
	if !repo.posting[board.ID].hidden.Load() || repo.posting[board.ID].noReprint.Load() {
		t.Fatal("independent policy")
	}
	var site siteState
	if strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site) != nil || site.MinimumReader < 76 {
		t.Fatal("reader migration")
	}
	for _, path := range []string{"/", "/bbsmenu.html", "/bbsmenu.json"} {
		rec := publicLocalRules(t, repo, path, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "secretboard") || !strings.Contains(rec.Body.String(), "visibleboard") {
			t.Fatal("board menu", path, rec.Code)
		}
	}
	for _, path := range []string{"/search"} {
		rec := publicLocalRules(t, repo, path, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "secretboard") || strings.Contains(rec.Body.String(), "秘密タイトル") || !strings.Contains(rec.Body.String(), "visibleboard") {
			t.Fatal("discovery", path, rec.Code, rec.Body.String())
		}
	}
	if rec := publicLocalRules(t, repo, "/search?board=secretboard", nil); rec.Code != 404 || strings.Contains(rec.Body.String(), "秘密タイトル") {
		t.Fatal("search bypass", rec.Code)
	}
	for _, ua := range []string{"Mozilla/5.0", "Monazilla/1.00 ChMate/0.8.10"} {
		for _, path := range []string{readPath, "/web/post?bbs=secretboard"} {
			for _, method := range []string{"GET", "HEAD", "POST"} {
				rec := hiddenPublicRequest(t, repo, method, path, http.Header{"User-Agent": {ua}, "Range": {"bytes=0-15"}})
				if rec.Code != 403 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Robots-Tag") == "" || strings.Contains(rec.Body.String(), "保存本文") {
					t.Fatal("web gate", method, path, rec.Code)
				}
			}
		}
	}
	dat := publicLocalRules(t, repo, datPath, http.Header{"User-Agent": {"Mozilla/5.0"}})
	if dat.Code != 200 || !bytes.Equal(dat.Body.Bytes(), original) {
		t.Fatal("DAT changed")
	}
	etag := dat.Header().Get("ETag")
	if publicLocalRules(t, repo, datPath, http.Header{"If-None-Match": {etag}}).Code != 304 {
		t.Fatal("conditional")
	}
	if publicLocalRules(t, repo, datPath, http.Header{"Range": {"bytes=0-15"}, "If-Range": {etag}}).Code != 206 {
		t.Fatal("range")
	}
	for _, path := range []string{"/secretboard/", "/secretboard/index.html", "/secretboard/subback.html", "/secretboard/subject.txt", "/secretboard/head.txt", "/secretboard/SETTING.TXT", datPath} {
		if rec := publicLocalRules(t, repo, path, nil); rec.Code != 200 {
			t.Fatal("direct access", path, rec.Code)
		} else if path == "/secretboard/" {
			if !strings.Contains(rec.Body.String(), "専用ブラウザ") || strings.Contains(rec.Body.String(), "この板を検索") || strings.Contains(rec.Body.String(), "スレッドを立てる") {
				t.Fatal("hidden board UI")
			}
		}
		if rec := publicLocalRules(t, repo, path, http.Header{"User-Agent": {"Googlebot"}}); rec.Code != 403 {
			t.Fatal("crawler", path, rec.Code)
		}
	}
	if publicLocalRules(t, repo, "/visibleboard/", http.Header{"User-Agent": {"Googlebot"}}).Code != 200 {
		t.Fatal("ordinary board crawler")
	}
	robots := publicLocalRules(t, repo, "/robots.txt", nil).Body.String()
	if !strings.Contains(robots, "Disallow: /secretboard/") || strings.Contains(robots, "/visibleboard/") {
		t.Fatal("robots")
	}
	res, body := client.request("GET", "/boards", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "secretboard") {
		t.Fatal("admin discovery", res.StatusCode)
	}
	res, body = client.request("GET", "/boards/"+board.ID.String()+"/settings", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `name="hidden"`) {
		t.Fatal("admin setting")
	}
	// 共通CGI投稿は隠し板も解決する。HTTPテストはブラウザフォームへ迂回しない。
	assertHiddenLegacyPosting(t, repo)
	form.Close()
	client.server.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if !repo.posting[board.ID].hidden.Load() || publicLocalRules(t, repo, readPath, nil).Code != 403 || publicLocalRules(t, repo, datPath, nil).Code != 200 {
		t.Fatal("recovery")
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	off := false
	save(&off)
	if publicLocalRules(t, repo, readPath, nil).Code != 200 || !strings.Contains(publicLocalRules(t, repo, "/", nil).Body.String(), "secretboard") || strings.Contains(publicLocalRules(t, repo, "/robots.txt", nil).Body.String(), "Disallow:") {
		t.Fatal("OFF restoration")
	}
}

func TestHiddenBoardStrictCompatibility(t *testing.T) {
	settings := defaultBoardSettings()
	raw, _ := json.Marshal(settings)
	if strings.Contains(string(raw), "hidden") {
		t.Fatal("legacy bytes")
	}
	var decoded boardSettings
	if strictjson.Decode(raw, &decoded) != nil || decoded.Presentation.unlisted() {
		t.Fatal("legacy decode")
	}
	on := true
	settings.Presentation.Hidden = &on
	raw, _ = json.Marshal(settings)
	if strictjson.Decode(raw, &decoded) != nil || !decoded.Presentation.unlisted() {
		t.Fatal("ON decode")
	}
	for _, replacement := range []string{`"hidden":"true"`, `"hidden":true,"hidden":false`, `"unknown":true`} {
		invalid := strings.Replace(string(raw), `"hidden":true`, replacement, 1)
		if strictjson.Decode([]byte(invalid), &decoded) == nil {
			t.Fatal("invalid accepted", replacement)
		}
	}
	fields := adminBoardFields(boardEdit(boardValue{Settings: settings}))
	edit, err := parseAdminBoardFields(fields)
	if err != nil || edit.Hidden == nil || !*edit.Hidden {
		t.Fatal("form parse", err)
	}
	fields.Set("hidden", "invalid")
	if _, err := parseAdminBoardFields(fields); err == nil {
		t.Fatal("form invalid")
	}
	if validateIdentityReader(siteState{MinimumReader: 75}, boardValue{Settings: settings}) == nil {
		t.Fatal("old reader accepted")
	}
}

// hiddenPublicRequest はHEADを含む公開ルーターの制限を確認する。
func hiddenPublicRequest(t *testing.T, repo *Repository, method, path string, headers http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, repo.cfg.Public.BaseURL+path, nil)
	for key, values := range headers {
		req.Header[key] = values
	}
	rec := httptest.NewRecorder()
	repo.SiteWebHandler(nil).ServeHTTP(rec, req)
	return rec
}

// assertHiddenLegacyPosting は実HTTPで専ブラの確認と再送による投稿成立を検査する。
func assertHiddenLegacyPosting(t *testing.T, repo *Repository) {
	t.Helper()
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "hidden-test")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	base, _ := url.Parse(repo.cfg.Public.BaseURL)
	fields := url.Values{"bbs": {"secretboard"}, "subject": {"専ブラ確認"}, "MESSAGE": {"専ブラ本文"}, "oimo_request_id": {"hidden-legacy-http"}}
	var cookies []*http.Cookie
	for step := 0; step < 2; step++ {
		req, _ := http.NewRequest("POST", server.URL+"/test/bbs.cgi", strings.NewReader(fields.Encode()))
		req.Host = base.Host
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		req.Header.Set("Origin", repo.cfg.Public.BaseURL)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		decoded, decodeErr := textcodec.Decode(raw)
		if err != nil || decodeErr != nil || res.StatusCode != 200 {
			t.Fatal("CGI", res.StatusCode, err, decodeErr)
		}
		if step == 0 {
			if !strings.Contains(decoded, "<!-- 2ch_X:cookie -->") {
				t.Fatal("CGI confirmation", decoded)
			}
			cookies = res.Cookies()
		} else if !strings.Contains(decoded, "投稿を受け付けました。") {
			t.Fatal("CGI submission", decoded)
		}
	}
}
