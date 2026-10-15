// 管理HTTPから板設定を変更し、確認・投稿停止・入力制限・復旧まで確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/postcapture"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func (c *adminClient) board(id string) (*http.Response, AdminBoard) {
	c.t.Helper()
	res, body := c.request("GET", "/api/v1/boards/"+id+"/settings", "", nil)
	var v struct {
		Data AdminBoard `json:"data"`
	}
	if e := json.Unmarshal([]byte(body), &v); e != nil {
		c.t.Fatal(e)
	}
	return res, v.Data
}
func TestAdminBoardPostingAndRecovery(t *testing.T) {
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
	path := "/api/v1/boards/" + info.ID.String() + "/settings"
	res, b := client.board(info.ID.String())
	if res.StatusCode != 200 || b.Settings.Input.BodyBytes != 4096 {
		t.Fatal("initial board")
	}
	form := formServer(t, repo, siteID(repo.site.State()), info.ID, true)
	defer func() { form.Close() }()
	create := url.Values{"bbs": {"news"}, "subject": {"first"}, "MESSAGE": {"first"}, "oimo_request_id": {"admin-board-create-01"}}
	accepted, e := sendForm(form, create)
	if e != nil || !accepted.Accepted {
		t.Fatal("create", accepted, e)
	}
	reply := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(accepted.Key)}, "MESSAGE": {"pending"}, "oimo_request_id": {"admin-board-reply-001"}}
	pending, e := sendFormOnce(form, reply, "")
	if e != nil || pending.Confirmation == nil {
		t.Fatal("confirmation", e)
	}
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"board-settings-test-0001"}}
	edit := b.Settings
	edit.Reply = "disabled"
	edit.Input.BodyBytes = 8
	raw, _ := json.Marshal(edit)
	res, _ = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode)
	}
	savedETag := res.Header.Get("ETag")
	changed, e := sendFormOnce(form, reply, pending.Confirmation.Token)
	if e != nil || changed.Confirmation == nil || changed.Accepted {
		t.Fatal("old confirmation accepted", e)
	}
	stopped, e := sendFormOnce(form, reply, changed.Confirmation.Token)
	if e != nil || stopped.Accepted || stopped.Confirmation != nil {
		t.Fatal("reply stop bypassed", stopped, e)
	}
	retry, e := sendForm(form, create)
	if e != nil || !retry.Duplicate || retry.Key != accepted.Key {
		t.Fatal("accepted retry lost", retry, e)
	}
	res, _ = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 200 || res.Header.Get("ETag") != savedETag {
		t.Fatal("duplicate mutation")
	}
	conflicting := edit
	conflicting.Input.BodyBytes = 9
	conflictRaw, _ := json.Marshal(conflicting)
	res, _ = client.request("PATCH", path, string(conflictRaw), headers)
	if res.StatusCode != 409 {
		t.Fatal("key conflict", res.StatusCode)
	}
	_, untouched := client.board(other.ID.String())
	if untouched.Settings.Reply != "anyone" || untouched.Settings.Input.BodyBytes != 4096 {
		t.Fatal("another board changed")
	}
	public, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+"/news/SETTING.TXT", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "BBS_MESSAGE_COUNT=8") {
		t.Fatal("public setting", w.Code, w.Body.String())
	}
	// 再起動後も設定・receiptが残り、公開済みスレッドを復旧できる。
	_, savedBoard := client.board(info.ID.String())
	form.Close()
	client.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	form = formServer(t, repo, siteID(repo.site.State()), info.ID, true)
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	res, recovered := client.board(info.ID.String())
	if !reflect.DeepEqual(recovered.Settings, savedBoard.Settings) || res.Header.Get("ETag") != savedETag {
		t.Fatal("settings not durable")
	}
	headers.Set("X-CSRF-Token", res.Header.Get("X-CSRF-Token"))
	res, _ = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 200 || res.Header.Get("ETag") != savedETag {
		t.Fatal("receipt not durable", res.StatusCode)
	}
	// 再開後は新しい上限を適用し、既存DATは維持する。
	edit.Reply = "anyone"
	edit.Create = "disabled"
	headers.Set("If-Match", savedETag)
	headers.Set("Idempotency-Key", "board-settings-test-0002")
	raw, _ = json.Marshal(edit)
	res, _ = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("resume", res.StatusCode)
	}
	reply.Set("MESSAGE", "123456789")
	denied, e := sendForm(form, reply)
	if e != nil || denied.Accepted {
		t.Fatal("size limit bypass", e)
	}
	reply.Set("MESSAGE", "12345678")
	yes, e := sendForm(form, reply)
	if e != nil || !yes.Accepted || yes.Number != 2 {
		t.Fatal("reply failed", yes, e)
	}
	create.Set("oimo_request_id", "admin-board-create-02")
	denied, e = sendForm(form, create)
	if e != nil || denied.Accepted {
		t.Fatal("create stop bypass", e)
	}
	snapshot, e := repo.Thread(context.Background(), info.ID, accepted.Key)
	if e != nil || snapshot == nil {
		t.Fatal("old thread lost", e)
	}
}

func TestAdminBoardCASFormAndValidation(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	path := "/api/v1/boards/" + info.ID.String() + "/settings"
	if res, _ := client.request("GET", path, "", nil); res.StatusCode != 401 {
		t.Fatal("unauthorized read")
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, b := client.board(info.ID.String())
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"board-invalid-setting-1"}}
	invalid := b.Settings
	invalid.Input.BodyLines = 3
	raw, _ := json.Marshal(invalid)
	if res, _ := client.request("PATCH", path, string(raw), headers); res.StatusCode != 422 {
		t.Fatal("odd lines accepted")
	}
	raw, _ = json.Marshal(b.Settings)
	bad := headers.Clone()
	bad.Set("X-CSRF-Token", "wrong")
	if res, _ := client.request("PATCH", path, string(raw), bad); res.StatusCode != 403 {
		t.Fatal("CSRF bypass")
	}
	bad = headers.Clone()
	bad.Set("Origin", "http://attacker.invalid")
	if res, _ := client.request("PATCH", path, string(raw), bad); res.StatusCode != 403 {
		t.Fatal("Origin bypass")
	}
	// 同時の版一致要求は一つだけ保存する。
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := headers.Clone()
			h.Set("Idempotency-Key", fmt.Sprintf("board-concurrent-%03d", i))
			res, _ := client.request("PATCH", path, string(raw), h)
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
	action := "/boards/" + info.ID.String() + "/settings"
	res, page := client.request("GET", action, "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "本文の行数上限") {
		t.Fatal("form unavailable")
	}
	_, b = client.board(info.ID.String())
	fields := adminBoardFields(b.Settings)
	hidden := pageFields(page)
	for _, key := range []string{"csrf", "revision", "request_id"} {
		fields.Set(key, hidden.Get(key))
	}
	fields.Set("body_lines", "3")
	formHeaders := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, page = client.request("POST", action, fields.Encode(), formHeaders)
	if res.StatusCode != 422 || !strings.Contains(page, `value="3"`) || !strings.Contains(page, fields.Get("request_id")) {
		t.Fatal("invalid input lost", res.StatusCode)
	}
	fields.Set("body_lines", "4")
	res, _ = client.request("POST", action, fields.Encode(), formHeaders)
	if res.StatusCode != 303 {
		t.Fatal("form save", res.StatusCode)
	}
	res, _ = client.request("POST", action, fields.Encode(), formHeaders)
	if res.StatusCode != 303 {
		t.Fatal("form retry", res.StatusCode)
	}
	fields.Set("request_id", "board-stale-form-0001")
	res, page = client.request("POST", action, fields.Encode(), formHeaders)
	if res.StatusCode != 412 || !strings.Contains(page, fields.Get("request_id")) {
		t.Fatal("stale form lost")
	}
	_, page = client.request("GET", "/boards", "", nil)
	if !strings.Contains(page, action) {
		t.Fatal("board list link missing")
	}
}

// 板controlの保存失敗は成功にせず、最低reader版だけ保存された状態も復旧できる。
func TestAdminBoardSaveFailureAndReset(t *testing.T) {
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
	path := "/api/v1/boards/" + info.ID.String() + "/settings"
	res, b := client.board(info.ID.String())
	edit := b.Settings
	edit.Create = "disabled"
	raw, _ := json.Marshal(edit)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"board-failed-save-0001"}}
	if e = repo.boards[info.ID].Close(); e != nil {
		t.Fatal(e)
	}
	res, _ = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 503 || res.Header.Get("X-Operation-ID") == "" {
		t.Fatal("failed save reported success", res.StatusCode)
	}
	client.server.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("feature gate only recovery", e)
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	res, b = client.board(info.ID.String())
	if b.Settings.Create != "anyone" {
		t.Fatal("failed settings published")
	}
	headers.Set("X-CSRF-Token", res.Header.Get("X-CSRF-Token"))
	res, _ = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("retry failed", res.StatusCode)
	}
	client.server.Close()
	if _, e = repo.ConfigureAdministrator("owner", "所有者", "replacement-board-admin-password", true); e != nil {
		t.Fatal("reader version regressed", e)
	}
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reset recovery", e)
	}
	boards, e := repo.Boards()
	if e != nil || len(boards) != 1 {
		t.Fatal("edited board inspection", e)
	}
}

// 名無し名の上限はHTML一般escapeではなく、実際のDATに使うescapeで判定する。
func TestAdminBoardDefaultNameDATLimit(t *testing.T) {
	edit := boardEdit(boardValue{Settings: defaultBoardSettings()})
	edit.Input.Noname = `"`
	edit.Input.NameBytes = 5
	if e := edit.validate(); e == nil {
		t.Fatal("DAT &quot; needs six bytes")
	}
	edit.Input.NameBytes = 6
	if e := edit.validate(); e != nil {
		t.Fatal("exact DAT limit", e)
	}
}
