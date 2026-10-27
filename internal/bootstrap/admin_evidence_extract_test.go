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
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
)

func TestEvidenceExtractFromDraft(t *testing.T) {
	for _, mode := range []string{"missing", "saved-extract", "saved-exports"} {
		t.Run(mode, func(t *testing.T) { testEvidenceExtractFromDraft(t, mode) })
	}
}

func testEvidenceExtractFromDraft(t *testing.T, mode string) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, e := repo.CreateBoard(t.Context(), "extract", "提出検証")
	if e != nil {
		t.Fatal(e)
	}
	fs := formServer(t, repo, siteID(repo.site.State()), board.ID)
	posted, e := sendForm(fs, url.Values{"bbs": {"extract"}, "subject": {"対象スレッド"}, "FROM": {"投稿者"}, "MESSAGE": {"PRIVATE-EXTRACT-BODY"}, "oimo_request_id": {"extract-post-00001"}})
	defer fs.Close()
	if e != nil || !posted.Accepted {
		t.Fatal("post", e)
	}

	wantCount := uint32(1)
	var finishedAt string
	if mode != "missing" {
		reply, err := sendForm(fs, url.Values{"bbs": {"extract"}, "key": {strconv.FormatUint(posted.Key, 10)}, "MESSAGE": {"MISSING-RESPONSE-BODY"}, "oimo_request_id": {"extract-post-00002"}})
		if err != nil || !reply.Accepted {
			t.Fatal("second post", err)
		}
		wantCount = 2
		public := optionalProductServer(t, repo)
		res, err := public.Client().Get(public.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		public.Close()
		if err = repo.optionalQueue.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		records := optionalProductRecords(t, cfg, siteID(repo.site.State()))
		scope := disclosure.Scope{Board: board.ID, Thread: domain.U64(posted.Key), From: domain.Time(time.Now().Add(-time.Hour).UnixNano()), To: domain.Time(time.Now().UnixNano())}
		accepted, err := repo.collectEvidence(t.Context(), scope)
		if err != nil || len(accepted) != 2 || len(records) == 0 {
			t.Fatal("accepted fixture", err)
		}
		optional := records[0]
		optional.ID = domain.NewID()
		optional.Board, optional.Operation = &board.ID, &accepted[0].Operation
		optional.Received = accepted[0].Committed
		optional.Finished = optional.Received + 100
		optional.Until = optional.Received + domain.Time(evidence.OptionalRetention)
		optional.Method, optional.Route, optional.Kind, optional.Outcome = "POST", "legacy_post", "response", "accepted"
		bindAcceptedResponseFixture(t, &optional, accepted[0])
		if err = repo.optionalStore.Write(t.Context(), optional); err != nil {
			t.Fatal(err)
		}
		finishedAt = time.Unix(0, int64(optional.Finished)).In(domain.JST).Format(time.RFC3339Nano)
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
	res, _, _ = evidencePost(t, c, "/api/v1"+path, map[string]any{"reason": current.Reason, "columns": []string{"content"}}, current.ETag(), ownerTokens["/api/v1"+path], domain.NewID().String())
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
	if len(form) != 2 || !strings.Contains(form[1], "ZIPを作成してダウンロード") || strings.Contains(page, "<summary>提出ZIPを作成</summary>") || strings.Contains(form[1], `type="checkbox"`) {
		t.Fatal("draft actions")
	}
	fields = pageFields(form[1])
	fields.Set("reason", current.Reason)
	for _, column := range []string{"connection", "content"} {
		old, _ := url.ParseQuery(fields.Encode())
		old.Set(column, "on")
		if response, _ := c.request("POST", path, old.Encode(), headers); response.StatusCode != 400 {
			t.Fatal("removed form selection accepted", column, response.StatusCode)
		}
	}
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

	extraExports := 0
	if mode == "saved-exports" {
		held, tokens := evidenceInfo(t, c, current.ID)
		hold := "/api/v1/evidence/cases/" + current.ID.String() + "/hold"
		response, held, body := evidencePost(t, c, hold, evidenceInput{Reason: current.Reason}, held.ETag(), tokens[hold], domain.NewID().String())
		if response.StatusCode != 200 {
			t.Fatal("hold before export", response.StatusCode, body)
		}
		held, tokens = evidenceInfo(t, c, current.ID)
		exports := "/api/v1/evidence/cases/" + current.ID.String() + "/exports"
		originalETag, exportKey := held.ETag(), domain.NewID().String()
		response, generated, body := evidencePost(t, c, exports, evidenceInput{Reason: current.Reason}, originalETag, tokens[exports], exportKey)
		if response.StatusCode != 200 || generated.HTTP == nil || generated.HTTP.State != "active" || len(generated.HTTP.Items) != 1 {
			t.Fatal("automatic HTTP hold", response.StatusCode, body)
		}
		response, replayed, body := evidencePost(t, c, exports, evidenceInput{Reason: current.Reason}, originalETag, tokens[exports], exportKey)
		if response.StatusCode != 200 || len(replayed.Exports) != 1 || replayed.Exports[0].ID != generated.Exports[0].ID {
			t.Fatal("export replay", response.StatusCode, body)
		}
		extraExports = 1
		_, page = c.request("GET", "/evidence", "", nil)
		form = regexp.MustCompile(`(?s)<form[^>]*action="` + regexp.QuoteMeta(path) + `"[^>]*>(.*?)</form>`).FindStringSubmatch(page)
		if len(form) != 2 {
			t.Fatal("active form")
		}
		fields = pageFields(form[1])
		fields.Set("reason", current.Reason)
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
	if e != nil || manifest.Count != wantCount || len(manifest.Columns) != 2 || manifest.Columns[0] != "connection" || manifest.Columns[1] != "content" {
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
	if len(csvRows) != int(wantCount) || csvRows[0]["thread_key"] == "" || csvRows[0]["record_id"] != "" {
		t.Fatal("CSV record")
	}
	if csvRows[0]["board_key"] != "extract" || csvRows[0]["thread_key"] != strconv.FormatUint(posted.Key, 10) {
		t.Fatal("posting target missing", csvRows[0])
	}
	if _, exists := csvRows[0]["request.board_alias_used"]; exists {
		t.Fatal("duplicate board key column")
	}
	if csvRows[0]["public_body"] != "PRIVATE-EXTRACT-BODY" || csvRows[0]["client.resolved_ip"] == "" {
		t.Fatal("full export fields missing", csvRows[0])
	}
	if mode == "missing" {
		if _, exists := csvRows[0]["time.response_finished_at_jst"]; exists {
			t.Fatal("unobserved response time column exported")
		}
	} else {
		if csvRows[0]["time.response_finished_at_jst"] != finishedAt || csvRows[1]["time.response_finished_at_jst"] != `\N` {
			t.Fatal("saved response time or missing value", csvRows)
		}
	}
	if _, exists := csvRows[0]["identity"]; exists {
		t.Fatal("empty identity column exported")
	}
	for column := range csvRows[0] {
		if !bytes.Contains(files["readme.txt"], []byte("- "+column+" [")) {
			t.Fatal("missing column explanation", column)
		}
	}
	repo.mu.Lock()
	finished, e := repo.evidenceCases.Get(current.ID)
	repo.mu.Unlock()
	if e != nil || finished.State != "active" || len(finished.Exports) != 1+extraExports || finished.Exports[extraExports].State != "consumed" || finished.Required == nil {
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
	if res, body = limited.request("POST", path, next.Encode(), headers); res.StatusCode != 200 {
		t.Fatal("active extraction", res.StatusCode, body)
	}
}
