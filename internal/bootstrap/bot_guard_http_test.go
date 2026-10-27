// 実HTTPで自動停止・通常再送・共有IP・閲覧・設定保存と旧形式互換を検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBotGuardPublicHTTPIsolationAndRetry(t *testing.T) {
	_, repo, site, owner := anonymousFixture(t, "required")
	defer repo.Close()
	server, request, cookies := anonymousHTTP(t, repo, site)
	defer server.Close()
	first := url.Values{"bbs": {"news"}, "subject": {"正常投稿"}, "MESSAGE": {"通常の本文"}, "oimo_request_id": {"bot-normal-create-0001"}}
	request("POST", "/test/bbs.cgi", first)
	response, body := request("POST", "/test/bbs.cgi", first)
	if response.StatusCode != 200 || strings.Contains(body, "ERROR:") {
		t.Fatal("initial accepted post", response.StatusCode, body)
	}
	confirmed := cookies["oimo_confirm"]
	stoppedCookie := cookies["oimo_anon"]
	var key uint64
	for k := range repo.posting[owner].threads {
		key = k
	}
	_, beforeDAT := request("GET", fmt.Sprintf("/news/dat/%d.dat", key), nil)
	_, page := request("GET", "/web/post?bbs=news", nil)
	fields := pageFields(page)
	fields.Set("subject", "不正フォーム")
	fields.Set("oimo_contact", "spam")
	seq := repo.site.State().Seq
	for i := 0; i < botFailureLimit; i++ {
		fields.Set("MESSAGE", fmt.Sprintf("bad-form-%d", i))
		request("POST", "/web/post?bbs=news", fields)
	}
	stats := repo.bot.stats(trafficNow())
	if stats.Stops != 1 || stats.Signals != botFailureLimit || repo.site.State().Seq != seq {
		t.Fatal("not automatically stopped or persisted failures", stats)
	}
	// DAT/subjectは停止Cookieを付けたまま読める。
	response, beforeSubject := request("GET", "/news/subject.txt", nil)
	if response.StatusCode != 200 {
		t.Fatal("reading blocked", response.StatusCode)
	}
	// 受理済みの同一再送は停止後も元結果へ戻る。
	cookies["oimo_confirm"] = confirmed
	response, body = request("POST", "/test/bbs.cgi", first)
	if response.StatusCode != 200 || strings.Contains(body, "ERROR:") {
		t.Fatal("accepted retry blocked", response.StatusCode, body)
	}
	newPost := url.Values{"bbs": {"news"}, "subject": {"新規投稿"}, "MESSAGE": {"別の通常本文"}, "oimo_request_id": {"bot-stopped-create-0001"}}
	response, body = request("POST", "/test/bbs.cgi", newPost)
	if response.StatusCode != 429 || response.Header.Get("Retry-After") == "" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("public stop response", response.StatusCode, response.Header, body)
	}
	for _, secret := range []string{"honeypot", "malformed_csrf", "automated malformed", "subject_hmac"} {
		if strings.Contains(body, secret) {
			t.Fatal("reason exposed", secret)
		}
	}
	_, afterSubject := request("GET", "/news/subject.txt", nil)
	if beforeSubject != afterSubject {
		t.Fatal("failed posts changed subject")
	}
	response, afterDAT := request("GET", fmt.Sprintf("/news/dat/%d.dat", key), nil)
	if response.StatusCode != 200 || beforeDAT != afterDAT {
		t.Fatal("stop/retry changed DAT")
	}
	// 別Cookieなら同じIPでもBot停止の対象にならない（既存のIP投稿枠は独立）。
	other, err := repo.anonymousCookie("", netip.MustParseAddr("127.0.0.1"), time.Now)
	if err != nil || other == nil {
		t.Fatal("second cookie", err)
	}
	cookies["oimo_anon"] = other
	newPost.Set("key", fmt.Sprint(key))
	newPost.Del("subject")
	newPost.Set("oimo_request_id", "bot-other-cookie-0001")
	response, body = request("POST", "/test/bbs.cgi", newPost)
	if response.StatusCode != 200 || strings.Contains(body, "ERROR:") || repo.bot.stats(trafficNow()).Rejected != stats.Rejected+1 {
		t.Fatal("other cookie counted as stopped", response.StatusCode)
	}
	// Web側も同じ停止を適用し、入力をエラー画面に保持する。
	cookies["oimo_anon"] = stoppedCookie
	_, page = request("GET", fmt.Sprintf("/web/post?bbs=news&key=%d", key), nil)
	webFields := pageFields(page)
	webFields.Set("MESSAGE", "入力保持の確認")
	response, body = request("POST", "/web/post?bbs=news", webFields)
	if response.StatusCode != 429 || response.Header.Get("Retry-After") == "" || !strings.Contains(body, "入力保持の確認") {
		t.Fatal("web stop/draft", response.StatusCode, body)
	}
	snapshot, err := repo.Thread(t.Context(), owner, key)
	if err != nil || snapshot.PostCount != 2 {
		t.Fatal("stored posts", snapshot, err)
	}
}

func TestBotGuardCSRFAndInvalidCookie(t *testing.T) {
	_, repo, site, owner := anonymousFixture(t, "required")
	defer repo.Close()
	server := formServer(t, repo, site, owner)
	defer server.Close()
	cookie, err := repo.anonymousCookie("", netip.MustParseAddr("127.0.0.1"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := repo.IssueWebCSRF(t.Context(), owner, "web_create")
	if err != nil {
		t.Fatal(err)
	}
	cookies := []http.Cookie{*csrf.Cookie, *cookie}
	fields := url.Values{"bbs": {"news"}, "subject": {"CSRF試験"}, "MESSAGE": {"本文"}, "csrf": {"broken"}}
	for i := 0; i < 20; i++ {
		if _, err := sendWeb(server, fields, cookies, repo.cfg.Public.BaseURL); err != nil {
			t.Fatal(err)
		}
	}
	if repo.bot.stats(trafficNow()).Signals != 1 {
		t.Fatal("retry counted")
	}
	for i := 1; i < botFailureLimit; i++ {
		fields.Set("MESSAGE", fmt.Sprint(i))
		if _, err := sendWeb(server, fields, cookies, repo.cfg.Public.BaseURL); err != nil {
			t.Fatal(err)
		}
	}
	if repo.bot.stats(trafficNow()).Stops != 1 {
		t.Fatal("malformed csrf not stopped")
	}
	// 欠落、期限切れ、署名だけの不一致は何度送っても追加カウントしない。
	old, err := abuse.IssueWebCSRF(csrf.Cookie.Value, "web_create", repo.posting[owner].csrfKey[:], 6, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", old, csrf.Token[:len(csrf.Token)-1] + "!"} {
		fields.Set("csrf", value)
		for i := 0; i < 10; i++ {
			fields.Set("MESSAGE", fmt.Sprint(i))
			if _, err := sendWeb(server, fields, cookies, repo.cfg.Public.BaseURL); err != nil {
				t.Fatal(err)
			}
		}
	}
	if repo.bot.stats(trafficNow()).Signals != botFailureLimit {
		t.Fatal("normal token failures counted")
	}
	fields.Set("oimo_contact", "spam")
	for _, raw := range []string{"", "forged-cookie"} {
		for i := 0; i < botFailureLimit; i++ {
			fields.Set("MESSAGE", fmt.Sprint(i))
			if _, err := sendWeb(server, fields, []http.Cookie{*csrf.Cookie, {Name: "oimo_anon", Value: raw}}, repo.cfg.Public.BaseURL); err != nil {
				t.Fatal(err)
			}
		}
	}
	if repo.bot.stats(trafficNow()).Signals != botFailureLimit {
		t.Fatal("unverified cookie remembered")
	}
}

func TestBotGuardSettingsCompatibilityAndRestart(t *testing.T) {
	v := defaultAbuseGuard()
	raw, _ := json.Marshal(v)
	legacy := strings.Replace(string(raw), `"bot_mode":"reject",`, "", 1)
	var parsed AbuseGuardSettings
	if err := strictjson.Decode([]byte(legacy), &parsed); err != nil || parsed.BotMode != "" {
		t.Fatal("old settings", err)
	}
	encoded, _ := json.Marshal(parsed)
	if string(encoded) != legacy {
		t.Fatal("old signed bytes changed", string(encoded))
	}
	for _, bad := range []string{strings.Replace(string(raw), `"bot_mode":"reject"`, `"bot_mode":null`, 1), strings.Replace(string(raw), `"bot_mode":"reject"`, `"bot_mode":"reject","bot_mode":"off"`, 1)} {
		if strictjson.Decode([]byte(bad), &parsed) == nil {
			t.Fatal("accepted invalid json")
		}
	}
	for _, mode := range []string{"off", "observe", "reject"} {
		t.Run(mode, func(t *testing.T) {
			cfg, repo := adminFixture(t)
			defer func() { repo.Close() }()
			c := newAdminClient(t, repo)
			defer c.server.Close()
			c.login(adminTestSecret)
			settings := defaultAbuseGuard()
			settings.BotMode = mode
			_, view := saveGuardSettings(t, c, settings, "bot-settings-save-0001")
			if view.Settings.BotMode != mode {
				t.Fatal(view)
			}
			res, page := c.request("GET", "/abuse-guard", "", nil)
			if res.StatusCode != 200 || !strings.Contains(page, `name="bot_mode"`) || !strings.Contains(page, "自動で一時停止") {
				t.Fatal("admin page")
			}
			if output := os.Getenv("OIMO_BOT_PAGE_OUTPUT"); output != "" && mode == "reject" {
				if err := os.WriteFile(output, []byte(page), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var site siteState
			if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader < botReader {
				t.Fatal("reader", err)
			}
			// 旧APIの省略更新では稼働中のモードを引き継ぐ。
			old := settings
			old.BotMode = ""
			old.TokenWaitSeconds++
			_, view = saveGuardSettings(t, c, old, "bot-settings-legacy-0001")
			if view.Settings.BotMode != mode {
				t.Fatal("legacy update reset mode")
			}
			c.server.Close()
			if err := repo.Close(); err != nil {
				t.Fatal(err)
			}
			var err error
			repo, err = OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal("restart", err)
			}
			if repo.bot.mode != mode || !reflect.DeepEqual(repo.bot.stats(trafficNow()), BotStats{}) {
				t.Fatal("restart state", repo.bot.mode)
			}
		})
	}
}

func TestBotGuardLegacyRetryAfterModeChange(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	settings := defaultAbuseGuard()
	settings.BotMode = "off"
	saveGuardSettings(t, c, settings, "bot-off-save-0001")
	res, _ := c.request("GET", "/api/v1/abuse-guard", "", nil)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"bot-legacy-retry-0001"}}
	legacy := settings
	legacy.BotMode = ""
	legacy.TokenWaitSeconds++
	raw, _ := json.Marshal(legacy)
	res, body := c.request("PATCH", "/api/v1/abuse-guard", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	priorETag := res.Header.Get("ETag")
	settings.BotMode = "observe"
	saveGuardSettings(t, c, settings, "bot-observe-save-0001")
	res, body = c.request("PATCH", "/api/v1/abuse-guard", string(raw), headers)
	if res.StatusCode != 200 || res.Header.Get("ETag") != priorETag || repo.bot.mode != "observe" {
		t.Fatal("later mode change broke old retry", res.StatusCode, body)
	}
}
