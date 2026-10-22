// ローカルルールの管理保存・公開・復旧・入力境界を検証する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/textcodec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalRulesValidation(t *testing.T) {
	rules, err := parseLocalRulesText("段落\r\n* 箇条書き\nhttps://example.com/?a=1&b=2\n<script>alert(1)</script>\n")
	if err != nil || len(rules) != 4 {
		t.Fatal(rules, err)
	}
	head, err := localRulesHead(rules)
	decoded, e := textcodec.Decode(head)
	if err != nil || e != nil || !strings.Contains(decoded, "&lt;script&gt;") || strings.Contains(decoded, "<script>") || !strings.Contains(decoded, "<li>箇条書き</li>") {
		t.Fatal(decoded, err, e)
	}
	if localRulesText(rules) != "段落\n* 箇条書き\nhttps://example.com/?a=1&b=2\n<script>alert(1)</script>" {
		t.Fatal("text roundtrip")
	}
	for _, rules := range [][]ruleParagraph{nil, {{Kind: "link", Text: "javascript:alert(1)"}}, {{Kind: "link", Text: "//example.com"}}, {{Kind: "link", Text: "https://user:password@example.com"}}, {{Kind: "html", Text: "<b>任意HTML</b>"}}, {{Kind: "paragraph", Text: "\x00"}}, {{Kind: "paragraph", Text: strings.Repeat("a", 2049)}}, {{Kind: "paragraph", Text: " "}}} {
		if validateLocalRules(rules) == nil {
			t.Fatal("invalid accepted", rules)
		}
	}
	if _, err := parseLocalRulesText(strings.Repeat("a\n", 129)); err == nil {
		t.Fatal("item limit")
	}
	if _, err := parseLocalRulesText(strings.Repeat(strings.Repeat("a", 2048)+"\n", 9)); err == nil {
		t.Fatal("total limit")
	}
}

func TestLocalRulesAdminPublicAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "localrules", "ローカルルール試験")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	api := "/api/v1/boards/" + board.ID.String() + "/local-rules"
	action := "/boards/" + board.ID.String() + "/local-rules"
	res, _ := c.request("GET", api, "", nil)
	if res.StatusCode != 200 {
		t.Fatal("get", res.StatusCode)
	}
	rules := LocalRules{Rules: []ruleParagraph{{Kind: "paragraph", Text: "利用案内<script>alert(1)</script>"}, {Kind: "item", Text: "荒らし禁止"}, {Kind: "link", Text: "https://example.com/rules"}}}
	raw, _ := json.Marshal(rules)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}}
	originalHeaders := headers.Clone()
	saved, body := c.request("PATCH", api, string(raw), headers)
	if saved.StatusCode != 200 {
		t.Fatal("save", saved.StatusCode, body)
	}
	repeated, _ := c.request("PATCH", api, string(raw), headers)
	if repeated.StatusCode != 200 || repeated.Header.Get("ETag") != saved.Header.Get("ETag") {
		t.Fatal("retry", repeated.StatusCode)
	}
	conflicting, _ := c.request("PATCH", api, `{"rules":[]}`, headers)
	if conflicting.StatusCode != 409 {
		t.Fatal("request conflict", conflicting.StatusCode)
	}
	headers.Set("Idempotency-Key", domain.NewID().String())
	conflict, _ := c.request("PATCH", api, string(raw), headers)
	if conflict.StatusCode != 412 {
		t.Fatal("CAS", conflict.StatusCode)
	}
	headers.Set("If-Match", saved.Header.Get("ETag"))
	headers.Set("X-CSRF-Token", "invalid")
	denied, _ := c.request("PATCH", api, string(raw), headers)
	if denied.StatusCode != 403 {
		t.Fatal("CSRF", denied.StatusCode)
	}
	assertLocalRulesPublic(t, repo, "localrules", "利用案内&lt;script&gt;", false)
	b := repo.posting[board.ID]
	if _, err := b.worker.Submit(t.Context(), func() (any, error) {
		h := store.Header{Kind: 2, Owner: board.ID, BaseSeq: uint64(b.control.State().Seq), Generation: 2}
		raw, e := store.EncodeControlSnapshot(h, b.control.State(), 6, snapshotBoardValue)
		if e != nil {
			return nil, e
		}
		_, e = store.DecodeControlSnapshot(raw, h, snapshotBoardValue)
		return nil, e
	}); err != nil {
		t.Fatal("snapshot", err)
	}

	// 期限切れの再送記録だけを既存の整理から回収し、ルール本体は維持する。
	session, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	old := domain.Time(time.Now().Add(-25 * time.Hour).UnixNano())
	expired := localRulesReceipt{ID: domain.NewID(), Admin: session.Admin, Key: domain.Hash{17}, Request: domain.Hash{18}, Result: AdminLocalRules{Board: board.ID, Revision: b.control.State().Rows["local_rules:active"].Revision, Settings: rules}, Created: old, Expires: old + 86400e9}
	if _, err := b.worker.Submit(t.Context(), func() (any, error) {
		return nil, appendControlAt(b.control, old, "receipt_fixture", []store.Mutation{mutation("local_rules_receipt", expired.Key.String(), expired, nil)})
	}); err != nil {
		t.Fatal("expired fixture", err)
	}
	if err := repo.EnableControlExpiry(t.Context()); err != nil {
		t.Fatal(err)
	}
	report, err := repo.SweepExpiredControl(t.Context(), 128)
	if err != nil || report.Boards != 1 {
		t.Fatal("receipt expiry", report, err)
	}
	if _, ok := b.control.State().Rows["local_rules:active"]; !ok {
		t.Fatal("active local rules removed")
	}
	// オンラインコピーも新しいcontrol設定を復旧できる。
	pin, err := repo.PinBoardBackup(t.Context(), board.ID, OnlineBackupGroupOptions{})
	if err != nil {
		t.Fatal("backup pin", err)
	}
	output := onlineOutput(t, "local-rules")
	cut, err := pin.Copy(t.Context(), output)
	pin.Close()
	if err != nil {
		t.Fatal("backup copy", err)
	}
	copied, err := store.OpenControlWithValidators(filepath.Join(output, "board", board.ID.String(), "control"), 2, board.ID, 0, validateBoardValue, snapshotBoardValue)
	if err != nil {
		t.Fatal("backup control", err)
	}
	err = validateOnlineBoardCopy(t.Context(), output, b, copied, cut.Captures)
	copied.Close()
	if err != nil {
		t.Fatal("backup validation", err)
	}
	// 公開ETagは保存内容の変更で切り替わる。
	before := publicLocalRules(t, repo, "/localrules/head.txt", nil)
	_, page := c.request("GET", action, "", nil)
	fields := pageFields(page)
	fields.Set("text", "新しい案内\n* 新しい箇条書き\nhttps://example.com/new")
	edited, _ := c.request("POST", action, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if edited.StatusCode != 303 {
		t.Fatal("HTML save", edited.StatusCode)
	}
	after := publicLocalRules(t, repo, "/localrules/head.txt", http.Header{"If-None-Match": {before.Header().Get("ETag")}})
	if after.Code != 200 || after.Header().Get("ETag") == before.Header().Get("ETag") {
		t.Fatal("stale ETag")
	}
	conditional := publicLocalRules(t, repo, "/localrules/head.txt", http.Header{"If-None-Match": {after.Header().Get("ETag")}})
	if conditional.Code != 304 || conditional.Body.Len() != 0 {
		t.Fatal("conditional")
	}
	_, page = c.request("GET", action, "", nil)
	fields = pageFields(page)
	fields.Set("text", strings.Repeat("a", 2049))
	invalid, invalidBody := c.request("POST", action, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if invalid.StatusCode != 422 || !strings.Contains(invalidBody, fields.Get("text")) {
		t.Fatal("invalid form retention", invalid.StatusCode)
	}
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	if report, err := Check(cfg); err != nil || report.MinimumReader != 72 {
		t.Fatal("reader/check", report, err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("recovery", err)
	}
	assertLocalRulesPublic(t, repo, "localrules", "新しい案内", false)
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("recovered login")
	}
	fresh, _ := c.request("GET", api, "", nil)
	originalHeaders.Set("X-CSRF-Token", fresh.Header.Get("X-CSRF-Token"))
	recoveredRetry, _ := c.request("PATCH", api, string(raw), originalHeaders)
	if recoveredRetry.StatusCode != 200 || recoveredRetry.Header.Get("ETag") != saved.Header.Get("ETag") {
		t.Fatal("recovered receipt", recoveredRetry.StatusCode)
	}
	assertLocalRulesPublic(t, repo, "localrules", "新しい案内", false)
	_, page = c.request("GET", action, "", nil)
	fields = pageFields(page)
	fields.Set("text", "")
	cleared, _ := c.request("POST", action, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if cleared.StatusCode != 303 {
		t.Fatal("clear", cleared.StatusCode)
	}
	assertLocalRulesPublic(t, repo, "localrules", "", true)
}

// publicLocalRules は公開ルーターのGETとHTTP検証子を同じ経路で検査する。
func publicLocalRules(t *testing.T, repo *Repository, path string, headers http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+path, nil)
	for key, values := range headers {
		req.Header[key] = values
	}
	rec := httptest.NewRecorder()
	repo.SiteWebHandler(nil).ServeHTTP(rec, req)
	return rec
}

// assertLocalRulesPublic は板トップ・一覧・専ブラ断片の表示とHTMLエスケープを検査する。
func assertLocalRulesPublic(t *testing.T, repo *Repository, slug, want string, empty bool) {
	t.Helper()
	for _, path := range []string{"/" + slug + "/", "/" + slug + "/index.html", "/" + slug + "/subback.html", "/" + slug + "/head.txt"} {
		rec := publicLocalRules(t, repo, path, nil)
		body := rec.Body.String()
		if strings.HasSuffix(path, "head.txt") {
			var err error
			body, err = textcodec.Decode(rec.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
		}
		if rec.Code != 200 || !strings.Contains(body, want) || strings.Contains(body, "<script>alert(1)</script>") {
			t.Fatal("public", path, rec.Code, body)
		}
		if empty && strings.HasSuffix(path, "head.txt") && body != "" {
			t.Fatal("cleared head")
		}
	}
}

func TestLocalRulesBoardScope(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	own, err := repo.CreateBoard(t.Context(), "ruleown", "担当板")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "ruleother", "担当外")
	if err != nil {
		t.Fatal(err)
	}
	owner := newAdminClient(t, repo)
	defer owner.server.Close()
	if owner.login(adminTestSecret) != 303 || owner.reauth(adminTestSecret) != 200 {
		t.Fatal("owner login")
	}
	list, _ := owner.request("GET", "/api/v1/administrators", "", nil)
	input := accountInput{Login: "local.rules.manager", Display: "板管理者", Password: "local-rules-manager-private-password", Access: AdministratorAccess{Role: "board_admin", Boards: []domain.ID{own.ID}, Permissions: []string{}, Enabled: true}}
	response, _, body := owner.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if response.StatusCode != 200 {
		t.Fatal("account", response.StatusCode, body)
	}
	limited := newAdminClient(t, repo)
	defer limited.server.Close()
	_, page := limited.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", input.Login)
	fields.Set("password", input.Password)
	response, _ = limited.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 303 {
		t.Fatal("limited login", response.StatusCode)
	}
	path := "/api/v1/boards/" + own.ID.String() + "/local-rules"
	response, _ = limited.request("GET", path, "", nil)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {response.Header.Get("ETag")}, "X-Csrf-Token": {response.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}}
	response, _ = limited.request("PATCH", path, `{"rules":[{"kind":"paragraph","text":"担当板の案内"}]}`, headers)
	if response.StatusCode != 200 {
		t.Fatal("assigned board edit", response.StatusCode)
	}
	path = "/api/v1/boards/" + other.ID.String() + "/local-rules"
	response, _ = limited.request("GET", path, "", nil)
	if response.StatusCode != 403 && response.StatusCode != 404 {
		t.Fatal("outside board disclosed")
	}
	session, err := repo.adminAuth.Lookup(limited.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	empty := LocalRules{Rules: []ruleParagraph{}}
	if _, err := repo.adminLocalRules(t.Context(), session, other.ID, &empty, "ignored", domain.NewID().String()); err != nil {
		var denied *adminFailure
		if !errors.As(err, &denied) || denied.status != 403 {
			t.Fatal("outside board mutation authorization", err)
		}
	} else {
		t.Fatal("outside board mutation")
	}
	response, _ = limited.request("PATCH", path, `{"rules":[]}`, headers)
	if response.StatusCode == 200 {
		t.Fatal("outside board edit")
	}
}
