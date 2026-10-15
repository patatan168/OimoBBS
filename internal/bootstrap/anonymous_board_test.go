// 板別Cookieと待ち時間を管理・実HTTP投稿・正本復旧で検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func anonymousAdminFixture(t *testing.T, mode string) (Config, *Repository, domain.ID) {
	t.Helper()
	cfg, repo := adminFixture(t)
	info, e := repo.CreateBoard(context.Background(), "news", "Cookie試験")
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
	if _, e = repo.EnableAnonymous(mode); e != nil {
		t.Fatal(e)
	}
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	return cfg, repo, info.ID
}
func saveAnonymousBoard(t *testing.T, c *adminClient, board domain.ID, mode string, wait uint32, requestID string) AdminBoard {
	t.Helper()
	res, v := c.board(board.String())
	edit := v.Settings
	edit.Anonymous = &AdminAnonymousSettings{mode, wait}

	raw, _ := json.Marshal(edit)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {requestID}}
	res, body := c.request("PATCH", "/api/v1/boards/"+board.String()+"/settings", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("save anonymous board", res.StatusCode, body)
	}
	_, v = c.board(board.String())
	return v
}
func TestBoardAnonymousModesAndRecovery(t *testing.T) {
	cfg, repo, board := anonymousAdminFixture(t, "required")
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	saveAnonymousBoard(t, c, board, "required", 0, "anonymous-board-required-01")
	server, request, cookies := anonymousHTTP(t, repo, siteID(repo.site.State()))
	defer server.Close()
	fields := url.Values{"bbs": {"news"}, "subject": {"Cookie必須"}, "MESSAGE": {"本文"}, "oimo_request_id": {"cookie-board-create-01"}}
	res, page := request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || !strings.Contains(page, "2ch_X:cookie") || cookies["oimo_anon"] == nil {
		t.Fatal("first confirmation", res.StatusCode, page)
	}
	token := cookies["oimo_anon"]
	delete(cookies, "oimo_anon")
	res, page = request("POST", "/test/bbs.cgi", fields)
	rows, _ := repo.rateHistory()
	if res.StatusCode != 200 || !strings.Contains(page, "2ch_X:cookie") || len(rows) != 0 {
		t.Fatal("required bypass", res.StatusCode, page)
	}
	cookies["oimo_anon"] = token
	res, page = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || (strings.Contains(page, "ERROR:") || strings.Contains(page, "2ch_X:cookie")) {
		t.Fatal("returned token", res.StatusCode, page)
	}
	rows, _ = repo.rateHistory()
	if len(rows) != 1 || len(rows[0].record.Keys) != 4 {
		t.Fatal("token cost")
	}
	var key uint64
	// create record.Target is zero; use thread map for reply.
	for v := range repo.posting[board].threads {
		key = v
	}
	reply := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(key)}, "MESSAGE": {"返信本文"}, "oimo_request_id": {"cookie-board-reply-001"}}
	saveAnonymousBoard(t, c, board, "required", 30, "anonymous-board-wait-001")
	reply.Set("oimo_request_id", "cookie-board-reply-002")
	reply.Set("MESSAGE", "待ち時間")
	request("POST", "/test/bbs.cgi", reply)
	res, page = request("POST", "/test/bbs.cgi", reply)
	if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" {
		t.Fatal("wait bypass", res.StatusCode, page)
	}
	rows, _ = repo.rateHistory()
	if len(rows) != 1 {
		t.Fatal("wait wrote post")
	}
	// 待ち時間経過済みの署名Cookieなら同じ確認を再送して受理する。
	anon, e := repo.anonymous.verify(token.Value, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	anon.Issued = time.Now().Unix() - 31
	anon.Expires = anon.Issued + 30*86400
	signed, e := abuse.IssueAnon(anon, repo.anonymous.key[:], 4)
	if e != nil {
		t.Fatal(e)
	}
	cookies["oimo_anon"] = &http.Cookie{Name: "oimo_anon", Value: signed}
	res, page = request("POST", "/test/bbs.cgi", reply)
	if res.StatusCode != 200 || (strings.Contains(page, "ERROR:") || strings.Contains(page, "2ch_X:cookie")) {
		t.Fatal("wait completion", res.StatusCode, page)
	}
	assertAnonymousPrincipalProjection(t, repo, board, repo.anonymous.subject(anon.ID), signed)
	c.server.Close()
	server.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("recovery", e)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	_, v := c.board(board.String())
	if v.Settings.anonymous() != (AdminAnonymousSettings{"required", 30}) {
		t.Fatal("cookie settings lost")
	}
	// 旧API形の更新でCookie規制が意図せず解除されない。
	res, current := c.board(board.String())
	current.Settings.Anonymous = nil
	raw, _ := json.Marshal(current.Settings)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"anonymous-legacy-edit-01"}}
	res, body := c.request("PATCH", "/api/v1/boards/"+board.String()+"/settings", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("legacy edit", res.StatusCode, body)
	}
	_, current = c.board(board.String())
	if current.Settings.anonymous() != (AdminAnonymousSettings{"required", 30}) {
		t.Fatal("legacy request weakened cookie policy")
	}
	saveAnonymousBoard(t, c, board, "required", 0, "anonymous-reset-wait-001")
	// snapshot検証も新しい編集範囲を受け付ける。
	row := repo.boards[board].State().Rows["board:state"]
	if e := snapshotBoardValue("board", "state", nil, row.Value); e != nil {
		t.Fatal("snapshot", e)
	}
}

func TestAnonymousWaitAndCompleteSettings(t *testing.T) {
	start := time.Unix(1000, 0)
	token := abuse.Anon{ID: domain.NewID(), Issued: start.Unix(), Expires: 2000, Generation: 1}
	for _, tc := range []struct {
		at   time.Time
		want uint64
	}{{start, 30}, {start.Add(29*time.Second + time.Nanosecond), 1}, {start.Add(30 * time.Second), 0}} {
		e := anonymousWait(token, 30, tc.at)
		if tc.want == 0 {
			if e != nil {
				t.Fatal(e)
			}
			continue
		}
		limited, ok := e.(*abuse.RateLimited)
		if !ok || limited.RetryAfter != tc.want {
			t.Fatal("retry boundary", e)
		}
	}
	if e := anonymousWait(abuse.Anon{}, 30, start); e == nil {
		t.Fatal("missing token")
	}
	old := boardEdit(boardValue{Settings: defaultBoardSettings()})
	raw, _ := json.Marshal(old)
	var parsed AdminBoardEdit
	if e := strictjson.Decode(raw, &parsed); e != nil || parsed.Anonymous == nil {
		t.Fatal("legacy settings", e)
	}
	for _, extra := range []string{`,"anonymous":null`, `,"unknown":1`, `,"anonymous":{"cookie_mode":"required"}`} {
		broken := append(append([]byte{}, raw[:len(raw)-1]...), []byte(extra+"}")...)
		if strictjson.Decode(broken, &parsed) == nil {
			t.Fatal("bad settings", extra)
		}
	}
	for _, tc := range anonymousSettingsFixture(t).Cookies {
		if (tc.Settings.validate() == nil) != tc.Valid {
			t.Fatal("fixture cookie policy", tc)
		}
	}
	for _, siteMode := range []string{"required"} {
		a := &anonymousState{policy: AnonymousPolicy{Mode: siteMode}}
		mode, _ := effectiveAnonymous(a, boardPosting{Cookie: "off"})
		if siteMode == "required" && mode != "required" || siteMode == "optional" && mode != "off" {
			t.Fatal("site downgrade")
		}
	}
}

func TestBoardAnonymousOnlineActivation(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	info, e := repo.CreateBoard(context.Background(), "news", "オンライン有効化")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	saveAnonymousBoard(t, c, info.ID, "required", 30, "anonymous-online-enable-01")
	if repo.anonymous == nil || repo.admission == nil || repo.stopped || repo.posting[info.ID].stopped {
		t.Fatal("online activation did not resume")
	}
	path := "/boards/" + info.ID.String() + "/settings"
	_, page := c.request("GET", path, "", nil)
	fields := pageFields(page)
	// 実際のHTML入力項目を保存し、停止中の有効化案内が不要なことを検査する。
	_, current := c.board(info.ID.String())
	values := adminBoardFields(current.Settings)
	for k, v := range fields {
		values[k] = v
	}
	// チェック欄は保存用JSONではなく、ブラウザと同じ複数のコマンド値を送る。
	values.Del("display_commands")
	commands := regexp.MustCompile(`<input type="checkbox" name="display_commands" value="([^"]+)" checked`)
	for _, match := range commands.FindAllStringSubmatch(page, -1) {
		values.Add("display_commands", match[1])
	}
	values.Del("network_classes")
	values.Del("require_public_ip")
	values.Set("network_cidr", "")
	values.Set("network_kind", "unknown")
	values.Set("network_label", "")
	values.Set("network_suffix", "")
	values.Set("permit_foreign", "on")
	values.Set("permit_vpn", "on")
	values.Set("permit_unresolved_host", "on")
	for _, option := range permissionKinds {
		values.Set("permit_kind_"+option.Value, "on")
	}
	values["allow_country"] = strings.Fields(values.Get("country_scope"))
	values.Set("cookie_mode", "required")
	values.Set("token_wait_seconds", "0")
	res, body := c.request("POST", path, values.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("online HTML save", res.StatusCode, body)
	}
	c.server.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("recovery", e)
	}
	if repo.anonymous == nil {
		t.Fatal("activation lost")
	}
	if mode, _ := effectiveAnonymous(repo.anonymous, boardPosting{}); mode != "required" {
		t.Fatal("mandatory cookie lost")
	}
}

// anonymousPolicyFixture は設計の正常・境界・拒否値を束ねる合成データ。
type anonymousPolicyFixture struct {
	Schema  string `json:"schema"`
	Cookies []struct {
		Settings AdminAnonymousSettings `json:"settings"`
		Valid    bool                   `json:"valid"`
	} `json:"cookie_cases"`
	Rules []struct {
		Input AdminRuleInput `json:"input"`
		Valid bool           `json:"valid"`
	} `json:"rule_cases"`
}

// anonymousSettingsFixture は設計の独立した正常/境界/拒否値を実際の管理入力検査へ渡す。
func anonymousSettingsFixture(t *testing.T) anonymousPolicyFixture {
	t.Helper()
	var fixture anonymousPolicyFixture
	raw, e := os.ReadFile("../../docs/design/fixtures/cookie-and-rule-settings.json")
	if e != nil {
		t.Fatal(e)
	}
	if e := strictjson.Decode(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	if fixture.Schema != "cookie-rule-settings-v1" || len(fixture.Cookies) != 8 || len(fixture.Rules) != 9 {
		t.Fatal("incomplete fixture")
	}
	return fixture
}
