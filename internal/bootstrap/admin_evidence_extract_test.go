// 保全前からのZIP直接取得と、権限・CSRF・版競合・一回取得・署名を実HTTPで検査する。
package bootstrap

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestEvidenceExtractFromDraft(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, e := repo.CreateBoard(t.Context(), "extract", "提出検証")
	if e != nil {
		t.Fatal(e)
	}
	fs := formServer(t, repo, siteID(repo.site.State()), board.ID)
	posted, e := sendForm(fs, url.Values{"bbs": {"extract"}, "subject": {"対象スレッド"}, "FROM": {"投稿者"}, "MESSAGE": {"PRIVATE-EXTRACT-BODY"}, "oimo_request_id": {"extract-post-00001"}})
	fs.Close()
	if e != nil || !posted.Accepted {
		t.Fatal("post", e)
	}
	if _, e = repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.CreateAdministrator("exporter", "出力のみ", adminTestSecret, AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	// 番号を省略した実フォームで作成する。
	_, page := c.request("GET", "/evidence", "", nil)
	form := regexp.MustCompile(`(?s)<form method="post" action="/evidence/cases">(.*?)</form>`).FindStringSubmatch(page)
	if len(form) != 2 {
		t.Fatal("create form")
	}
	fields := pageFields(form[1])
	fields.Set("revision", `"evidence:new"`)
	fields.Set("board_id", board.ID.String())
	fields.Set("thread_key", strconv.FormatUint(posted.Key, 10))
	fields.Set("reason", "接続記録の提出")
	fields.Set("from", time.Now().Add(-time.Hour).In(domain.JST).Format("2006-01-02T15:04:05"))
	// 秒切り捨てで投稿日時を除外しないよう、確定後の上限を使う。
	fields.Set("to", time.Now().Format(time.RFC3339Nano))
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, _ := c.request("POST", "/evidence/cases", fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("create", res.StatusCode)
	}
	repo.mu.Lock()
	cases, e := repo.evidenceCases.Cases()
	repo.mu.Unlock()
	if e != nil || len(cases) != 1 || cases[0].State != "draft" || cases[0].Number == "" {
		t.Fatal("draft", e)
	}
	current := cases[0]
	path := "/evidence/cases/" + current.ID.String() + "/extract"
	_, ownerTokens := evidenceInfo(t, c, current.ID)
	res, _, _ = evidencePost(t, c, "/api/v1"+path, evidenceInput{Reason: current.Reason, Columns: []string{"invalid"}}, current.ETag(), ownerTokens["/api/v1"+path], domain.NewID().String())
	if res.StatusCode != 400 {
		t.Fatal("invalid columns", res.StatusCode)
	}
	legacy := "/api/v1/evidence/cases/" + current.ID.String() + "/exports"
	res, _, legacyError := evidencePost(t, c, legacy, evidenceInput{Reason: current.Reason}, current.ETag(), ownerTokens[legacy], domain.NewID().String())
	if res.StatusCode != 409 || !strings.Contains(legacyError, "EVIDENCE_HOLD_REQUIRED") {
		t.Fatal("draft prerequisite", res.StatusCode)
	}

	_, page = c.request("GET", "/evidence", "", nil)
	form = regexp.MustCompile(`(?s)<form[^>]*action="` + regexp.QuoteMeta(path) + `"[^>]*>(.*?)</form>`).FindStringSubmatch(page)
	if len(form) != 2 || !strings.Contains(form[1], "ZIPを作成してダウンロード") || strings.Contains(page, "<summary>提出ZIPを作成</summary>") {
		t.Fatal("draft actions")
	}
	fields = pageFields(form[1])
	fields.Set("reason", current.Reason)
	fields.Set("connection", "on")
	bad, _ := url.ParseQuery(fields.Encode())
	bad.Set("csrf", "invalid")
	if res, page = c.request("POST", path, bad.Encode(), headers); res.StatusCode != 400 || !strings.Contains(page, "画面を開き直") {
		t.Fatal("csrf guidance", res.StatusCode)
	}
	// 書き出しだけの権限で、保全の副作用が発生しない。
	limited := newAdminClient(t, repo)
	defer limited.server.Close()
	_, page = limited.request("GET", "/login", "", nil)
	login := pageFields(page)
	login.Set("login", "exporter")
	login.Set("password", adminTestSecret)
	if res, _ = limited.request("POST", "/login", login.Encode(), headers); res.StatusCode != 303 || limited.reauth(adminTestSecret) != 200 {
		t.Fatal("limited login")
	}
	_, page = limited.request("GET", "/evidence", "", nil)
	form = regexp.MustCompile(`(?s)<form[^>]*action="` + regexp.QuoteMeta(path) + `"[^>]*>(.*?)</form>`).FindStringSubmatch(page)
	// 記録権限を統合したため、保全前の記録も直接保全・出力できる。
	if len(form) != 2 {
		t.Fatal("combined record permission missing draft export")
	}

	repo.mu.Lock()
	unchanged, _ := repo.evidenceCases.Get(current.ID)
	repo.mu.Unlock()
	if unchanged.ETag() != current.ETag() {
		t.Fatal("unauthorized hold side effect")
	}
	res, body := c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/zip" {
		t.Fatal("extract", res.StatusCode, body)
	}
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), 32)
	if e != nil {
		t.Fatal(e)
	}
	signing := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(signing)
	manifest, e := disclosure.VerifyZIP(bytes.NewReader([]byte(body)), int64(len(body)), signing.Public().(ed25519.PublicKey))
	if e != nil || manifest.Count != 1 || len(manifest.Columns) != 1 || manifest.Columns[0] != "connection" {
		t.Fatal("signed ZIP", manifest, e)
	}
	archive, e := zip.NewReader(bytes.NewReader([]byte(body)), int64(len(body)))
	if e != nil {
		t.Fatal(e)
	}
	files := map[string][]byte{}
	for _, file := range archive.File {
		r, e := file.Open()
		if e != nil {
			t.Fatal(e)
		}
		raw, e := io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
		files[file.Name] = raw
	}
	if files["records.jsonl"] != nil || files["records.csv"] == nil {
		t.Fatal("new export is not CSV")
	}
	csvRows := evidenceCSVRows(t, files["records.csv"])
	if len(csvRows) != 1 || csvRows[0]["record_id"] == "" {
		t.Fatal("CSV record")
	}
	for column := range csvRows[0] {
		if !bytes.Contains(files["readme.txt"], []byte("- "+column+" [")) {
			t.Fatal("missing column explanation", column)
		}
	}
	repo.mu.Lock()
	finished, e := repo.evidenceCases.Get(current.ID)
	repo.mu.Unlock()
	if e != nil || finished.State != "active" || len(finished.Exports) != 1 || finished.Exports[0].State != "consumed" || finished.Required == nil {
		t.Fatal("audit state", e)
	}
	if res, _ = c.request("POST", path, fields.Encode(), headers); res.StatusCode != 412 {
		t.Fatal("duplicate produced another ZIP", res.StatusCode)
	}
	// 保全済みなら書き出し権限だけでも同じ画面から取得できる。
	_, page = limited.request("GET", "/evidence", "", nil)
	form = regexp.MustCompile(`(?s)<form[^>]*action="` + regexp.QuoteMeta(path) + `"[^>]*>(.*?)</form>`).FindStringSubmatch(page)
	if len(form) != 2 {
		t.Fatal("active extraction action")
	}
	next := pageFields(form[1])
	next.Set("reason", current.Reason)
	next.Set("connection", "on")
	if res, body = limited.request("POST", path, next.Encode(), headers); res.StatusCode != 200 {
		t.Fatal("active extraction", res.StatusCode, body)
	}
}
