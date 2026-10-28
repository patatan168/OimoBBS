// 板名・キー変更の認可、旧URL、投稿・再送・永続復旧と旧キーの再利用拒否を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
)

func metadataForm(t *testing.T, c *adminClient, id domain.ID) (string, url.Values) {
	t.Helper()
	path := "/boards/" + id.String() + "/metadata"
	res, body := c.request("GET", path, "", nil)
	if res.StatusCode != 200 {
		t.Fatal("metadata GET", res.StatusCode, body)
	}
	fields := pageFields(body)
	for _, match := range regexp.MustCompile(`<input name="(key|name)" value="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		fields.Set(match[1], html.UnescapeString(match[2]))
	}
	return path, fields
}

func TestAdminBoardMetadataURLsPostingAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	info, err := repo.CreateBoard(t.Context(), "original", "元の板")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("authentication")
	}
	form := formServer(t, repo, siteID(repo.site.State()), info.ID)
	defer form.Close()
	post := url.Values{"bbs": {"original"}, "subject": {"既存スレッド"}, "MESSAGE": {"既存本文"}, "oimo_request_id": {"metadata-before-0001"}}
	first, err := sendForm(form, post)
	if err != nil || !first.Accepted {
		t.Fatal("initial post", first, err)
	}
	before, err := repo.Thread(t.Context(), info.ID, first.Key)
	if err != nil {
		t.Fatal(err)
	}
	path, fields := metadataForm(t, c, info.ID)
	fields.Set("key", "renamed")
	fields.Set("name", "新しい板")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, body := c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("rename", res.StatusCode, body)
	}
	res, _ = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("idempotent rename", res.StatusCode)
	}
	_, board := c.board(info.ID.String())
	if board.Key != "renamed" || board.Name != "新しい板" {
		t.Fatal("settings presentation", board)
	}
	// 板設定receiptを作った後も、作成jobとの整合性と再起動を維持する。
	api := "/api/v1/boards/" + info.ID.String() + "/settings"
	get, _ := c.request("GET", api, "", nil)
	raw, _ := json.Marshal(board.Settings)
	res, body = c.request("PATCH", api, string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {get.Header.Get("ETag")}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"metadata-settings-0001"}})
	if res.StatusCode != 200 {
		t.Fatal("settings after rename", res.StatusCode, body)
	}
	public, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"original", "renamed"} {
		for _, suffix := range []string{"/", "/subject.txt", "/SETTING.TXT", "/dat/" + strconv.FormatUint(first.Key, 10) + ".dat"} {
			w := httptest.NewRecorder()
			public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+"/"+key+suffix, nil))
			if w.Code != 200 {
				t.Fatalf("%s%s: %d %s", key, suffix, w.Code, w.Body.String())
			}
			if suffix == "/SETTING.TXT" {
				text, e := textcodec.Decode(w.Body.Bytes())
				if e != nil || !strings.Contains(text, "BBS_TITLE=新しい板") {
					t.Fatal("legacy title", text, e)
				}
			}
		}
		w := httptest.NewRecorder()
		public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+"/test/read.cgi/"+key+"/"+strconv.FormatUint(first.Key, 10)+"/", nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "/test/read.cgi/renamed/") {
			t.Fatal("thread", key, w.Code, w.Body.String())
		}
	}
	after, err := repo.Thread(t.Context(), info.ID, first.Key)
	if err != nil || string(after.DAT) != string(before.DAT) {
		t.Fatal("rename changed existing DAT", err)
	}
	if _, err = repo.CreateBoard(context.Background(), "original", "新しい板"); err == nil {
		t.Fatal("old key reused")
	}
	// 変更前に開いた投稿フォームと新しいキーの両方で同じ板へ返信できる。
	for i, key := range []string{"original", "renamed"} {
		reply := url.Values{"bbs": {key}, "key": {strconv.FormatUint(first.Key, 10)}, "MESSAGE": {"変更後本文"}, "oimo_request_id": {"metadata-reply-" + key}}
		result, e := sendForm(form, reply)
		if e != nil || !result.Accepted || result.Number != uint32(i+2) {
			t.Fatal("reply", key, result, e)
		}
	}
	_, audit, _ := c.audit("action=board_metadata_update")
	if len(audit.Entries) != 1 || audit.Entries[0].ActorKind != "admin" {
		t.Fatal("metadata audit", audit)
	}
	c.server.Close()
	form.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("reopen", err)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("recovered login")
	}
	_, board = c.board(info.ID.String())
	if board.Key != "renamed" || board.Name != "新しい板" {
		t.Fatal("recovered metadata", board)
	}
	boards, err := repo.Boards()
	if err != nil || len(boards) != 1 || boards[0].Key != "renamed" || boards[0].Name != "新しい板" || boards[0].ID != info.ID {
		t.Fatal("board list", boards, err)
	}
	// 新しいキーで保存した設定receiptも、次の起動で検証できる。
	get, board = c.board(info.ID.String())
	raw, _ = json.Marshal(board.Settings)
	res, _ = c.request("PATCH", api, string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {get.Header.Get("ETag")}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"metadata-settings-0002"}})
	if res.StatusCode != 200 {
		t.Fatal("recovered settings", res.StatusCode)
	}
	verifyRenamedBoardBackup(t, repo, cfg)
	for range 2 {
		if _, err = repo.EnableControlSnapshots(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	candidate := filepath.Join(candidateParent(t), "board-metadata")
	if _, err = repo.PrepareControlSnapshot(t.Context(), candidate, 6); err != nil {
		t.Fatal("snapshot", err)
	}
	c.server.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = ActivateControlSnapshot(t.Context(), cfg, candidate, postcapture.Validate); err != nil {
		t.Fatal("activate", err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("snapshot recovery", err)
	}
	got, err := repo.webBoard("original")
	if err != nil || got == nil || got.Key != "renamed" || got.Name != "新しい板" {
		t.Fatal("snapshot metadata", got, err)
	}
}

// verifyRenamedBoardBackup は元の作成jobを残したまま、オンライン退避と隔離再生が成立することを確認する。
func verifyRenamedBoardBackup(t *testing.T, repo *Repository, cfg Config) {
	t.Helper()
	syncOnlineAudit(t, repo)
	body, keys, trust := onlineOutput(t, "body"), onlineOutput(t, "keys"), onlineOutput(t, "trust.json")
	work := filepath.Dir(onlineOutput(t, "work"))
	raw, err := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeNew(trust, raw); err != nil {
		t.Fatal(err)
	}
	report, err := repo.PrepareOnlineBackup(t.Context(), body, keys, work, OnlineBackupPreparationOptions{TrustInstance: trust, PartialPlan: onlineOutput(t, "body-plan.json"), PartialKeysPlan: onlineOutput(t, "keys-plan.json"), PairPlan: onlineOutput(t, "pair-plan.json")})
	if err != nil || !report.Complete || !report.Replay.Replayed {
		t.Fatal("renamed board backup/replay", report, err)
	}
}

func TestAdminBoardMetadataValidationAndReplay(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	one, err := repo.CreateBoard(t.Context(), "first", "最初")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CreateBoard(t.Context(), "second", "別の板"); err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path, fields := metadataForm(t, c, one.ID)
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, _ := c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 403 {
		t.Fatal("reauth required", res.StatusCode)
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	_, fields = metadataForm(t, c, one.ID)
	for _, key := range []string{"test", "web", "admin", "../escape", "Invalid", ""} {
		fields.Set("key", key)
		res, body := c.request("POST", path, fields.Encode(), headers)
		if res.StatusCode != 422 || !strings.Contains(body, `name="name"`) {
			t.Fatal("invalid key", key, res.StatusCode)
		}
	}
	fields.Set("key", "second")
	res, _ = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 409 {
		t.Fatal("existing key", res.StatusCode)
	}
	fields.Set("key", "third")
	fields.Set("csrf", "wrong")
	res, _ = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 403 {
		t.Fatal("csrf", res.StatusCode)
	}
	_, fields = metadataForm(t, c, one.ID)
	fields.Set("key", "third")
	stale := fields.Encode()
	res, body := c.request("POST", path, stale, headers)
	if res.StatusCode != 303 {
		t.Fatal("save", res.StatusCode, body)
	}
	fields.Set("request_id", domain.NewID().String())
	fields.Set("name", "古い画面")
	res, _ = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 412 {
		t.Fatal("stale form", res.StatusCode)
	}
	_, fields = metadataForm(t, c, one.ID)
	fields.Set("key", "first")
	fields.Set("name", "元のキーへ")
	res, _ = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("return to own alias", res.StatusCode)
	}
	res, _ = c.request("POST", path, stale, headers)
	if res.StatusCode != 303 {
		t.Fatal("old replay", res.StatusCode)
	}
	got, _ := repo.webBoard("third")
	if got == nil || got.Key != "first" || got.Name != "元のキーへ" {
		t.Fatal("replay rolled back newer metadata", got)
	}
	var site siteState
	if err = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader < boardMetadataReader {
		t.Fatal("reader boundary", err)
	}
}
