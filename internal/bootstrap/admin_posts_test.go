// 実HTTPのレス操作から、規制対象解決・削除・限定照会・署名CSV提出を検証する。
package bootstrap

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/disclosure"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
)

func postManagementFields(t *testing.T, page, path string) url.Values {
	t.Helper()
	match := regexp.MustCompile(`(?s)<form[^>]*action="` + regexp.QuoteMeta(path) + `"[^>]*>(.*?)</form>`).FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatal("missing management form", path)
	}
	return pageFields(match[1])
}

func TestAdminPostsManageAndExport(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	board, err := repo.CreateBoard(t.Context(), "manage", "管理レス検証")
	if err != nil {
		t.Fatal(err)
	}
	fs := formServer(t, repo, siteID(repo.site.State()), board.ID)
	first, err := sendForm(fs, url.Values{"bbs": {"manage"}, "subject": {"レス選択"}, "FROM": {"名前"}, "MESSAGE": {"FIRST-RESPONSE-CONTENT"}, "oimo_request_id": {"manage-create-00001"}})
	if err != nil || !first.Accepted {
		t.Fatal("first post", err)
	}
	second, err := sendForm(fs, url.Values{"bbs": {"manage"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"SECOND-RESPONSE-CONTENT"}, "oimo_request_id": {"manage-reply-000001"}})
	fs.Close()
	if err != nil || !second.Accepted {
		t.Fatal("second post", err)
	}
	if _, err = repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	base := fmt.Sprintf("/boards/%s/threads/%d/posts", board.ID, first.Key)
	res, page := c.request("GET", base+"/1", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "FIRST-RESPONSE-CONTENT") || !strings.Contains(page, "SECOND-RESPONSE-CONTENT") || strings.Contains(page, "127.0.0.1") || strings.Contains(page, "name=\"related\"") {
		t.Fatal("public-only management before reauth", res.StatusCode)
	}
	reauthPath := "/reauth?" + url.Values{"return_to": {base + "/1"}}.Encode()
	res, reauthPage := c.request("GET", reauthPath, "", nil)
	if res.StatusCode != 200 || !strings.Contains(reauthPage, reauthPath) {
		t.Fatal("reauth return path")
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	_, page = c.request("GET", base+"/1", "", nil)
	inspect := base + "/2/inspect"
	fields := postManagementFields(t, page, inspect)
	fields.Set("related", "post")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, private := c.request("POST", inspect, fields.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(private, "投稿操作ID") || !strings.Contains(private, "127.0.0.1") || strings.Count(private, "<dt>記録ID</dt>") != 1 {
		t.Fatal("selected second response", res.StatusCode)
	}
	// CSRFを別レスに流用できず、成功前の副作用も起こさない。
	before := repo.boards[board.ID].State().Seq
	if res, _ = c.request("POST", base+"/1/inspect", fields.Encode(), headers); res.StatusCode != 403 || repo.boards[board.ID].State().Seq != before {
		t.Fatal("cross-response CSRF")
	}
	// 同一スレッドの同じIPだけを選択し、CSV提出範囲にもその固定集合を使う。
	related := postManagementFields(t, private, inspect)
	related.Set("related", "ip")
	res, both := c.request("POST", inspect, related.Encode(), headers)
	if res.StatusCode != 200 || strings.Count(both, "<dt>記録ID</dt>") != 2 {
		t.Fatal("related IP selection", res.StatusCode)
	}
	b := repo.posting[board.ID]
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		journals := []*evidence.Journal{}
		for _, j := range b.journals {
			journals = append(journals, j)
		}
		_, err := app.AcceptedRecordsForPost(journals, board.ID, domain.U64(first.Key), 2, "ip", domain.Time(b.clock().UnixNano()), 1)
		if err != app.ErrEvidenceSelectionLimit {
			t.Fatal("selection silently truncated", err)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rulePath := base + "/2/rule"
	rule := postManagementFields(t, private, rulePath)
	rule.Set("kind", "ip")
	res, rulePage := c.request("POST", rulePath, rule.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(rulePage, `name="target" value="127.0.0.1"`) || !strings.Contains(rulePage, "規制する値を入力しました") {
		t.Fatal("IP automatic prefill", res.StatusCode)
	}
	// UAを識別子と混同せず、保存されたUAをそのまま使う。
	rule.Set("kind", "ua:0")
	res, rulePage = c.request("POST", rulePath, rule.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(rulePage, `value="ua" selected`) {
		t.Fatal("UA prefill", res.StatusCode)
	}
	rule.Set("kind", "token")
	if res, _ = c.request("POST", rulePath, rule.Encode(), headers); res.StatusCode != 422 {
		t.Fatal("absent anonymous subject invented")
	}
	// ZIPは選択時点の範囲で作成し、CSV/説明と既存の署名を含む。
	exportPath := base + "/2/export"
	export := postManagementFields(t, both, exportPath)
	export.Set("related", "ip")
	forged, _ := url.ParseQuery(export.Encode())
	forged.Set("selection", "changed")
	if res, _ = c.request("POST", exportPath, forged.Encode(), headers); res.StatusCode != 412 {
		t.Fatal("selection revision")
	}
	res, archiveBody := c.request("POST", exportPath, export.Encode(), headers)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/zip" {
		t.Fatal("ZIP extraction", res.StatusCode, archiveBody)
	}
	archive, err := zip.NewReader(bytes.NewReader([]byte(archiveBody)), int64(len(archiveBody)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, file := range archive.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[file.Name] = raw
	}
	rows := evidenceCSVRows(t, files["records.csv"])
	if len(rows) != 2 || files["readme.txt"] == nil || files["records.jsonl"] != nil {
		t.Fatal("export record count/format")
	}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row["post_number"]] = true
	}
	if !seen["1"] || !seen["2"] {
		t.Fatal("wrong response numbers")
	}
	seed, err := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), 32)
	if err != nil {
		t.Fatal(err)
	}
	signing := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(signing)
	manifest, err := disclosure.VerifyZIP(bytes.NewReader([]byte(archiveBody)), int64(len(archiveBody)), signing.Public().(ed25519.PublicKey))
	if err != nil || manifest.Count != 2 {
		t.Fatal("signed CSV ZIP", err)
	}
	// 同じ画面の削除は対象一レスだけ。再送は重複せず、記録は保持する。
	_, page = c.request("GET", base+"/1", "", nil)
	deletePath := base + "/2/delete"
	deletion := postManagementFields(t, page, deletePath)
	deletion.Set("confirm", "yes")
	res, _ = c.request("POST", deletePath, deletion.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("response deletion", res.StatusCode)
	}
	res, deleted := c.request("GET", base+"/1", "", nil)
	if res.StatusCode != 200 || !strings.Contains(deleted, "FIRST-RESPONSE-CONTENT") || strings.Contains(deleted, "SECOND-RESPONSE-CONTENT") || !strings.Contains(deleted, "あぼーん") {
		t.Fatal("deletion affected wrong response")
	}
	if res, _ = c.request("POST", deletePath, deletion.Encode(), headers); res.StatusCode != 303 {
		t.Fatal("deletion retry", res.StatusCode)
	}
	fields = postManagementFields(t, deleted, inspect)
	fields.Set("related", "post")
	res, private = c.request("POST", inspect, fields.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(private, "127.0.0.1") || strings.Contains(private, "SECOND-RESPONSE-CONTENT") {
		t.Fatal("deletion lost record or resurfaced body", res.StatusCode)
	}
	// 公開停止後も番号指定で記録を確認でき、公開原文を復活させない。
	_, deletePage := c.request("GET", base+"/1", "", nil)
	original := postManagementFields(t, deletePage, base+"/1/delete")
	raw := c.cookies["oimo_admin"].Value
	session, err := repo.adminAuth.Lookup(raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.ModerateThread(t.Context(), session, board.ID, first.Key, AdminModeration{Kind: "hide", Ranges: []app.RedactionRange{}}, original.Get("revision"), "manage-hide-thread")
	if err != nil {
		t.Fatal(err)
	}
	res, hidden := c.request("GET", base+"/1", "", nil)
	if res.StatusCode != 200 || strings.Contains(hidden, "FIRST-RESPONSE-CONTENT") {
		t.Fatal("hidden thread body surfaced")
	}
	lookup := postManagementFields(t, hidden, base+"/1/lookup")
	lookup.Set("response_number", "2")
	res, hiddenRecord := c.request("POST", base+"/1/lookup", lookup.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(hiddenRecord, "レス 2") || strings.Contains(hiddenRecord, "FIRST-RESPONSE-CONTENT") || strings.Contains(hiddenRecord, "SECOND-RESPONSE-CONTENT") {
		t.Fatal("hidden post lookup", res.StatusCode)
	}
	// URLにも一般監査にも接続IP・UA・匿名主体を複製しない。
	auditRes, auditBody := c.request("GET", "/api/v1/audit", "", nil)
	if auditRes.StatusCode != 200 || strings.Contains(auditBody, "127.0.0.1") || !strings.Contains(auditBody, "post_evidence_query") {
		t.Fatal("safe query audit", auditRes.StatusCode)
	}
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	snapshot, err := repo.Thread(t.Context(), board.ID, first.Key)
	if err != nil || snapshot != nil {
		t.Fatal("deletion restart", err)
	}
}

func TestAdminPostsPermissionsAndPublicSeparation(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	board, err := repo.CreateBoard(t.Context(), "limitedmanage", "担当板")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "othermanage", "別板")
	if err != nil {
		t.Fatal(err)
	}
	fs := formServer(t, repo, siteID(repo.site.State()), board.ID)
	posted, err := sendForm(fs, url.Values{"bbs": {"limitedmanage"}, "subject": {"対象"}, "MESSAGE": {"VISIBLE-RESPONSE"}, "oimo_request_id": {"limited-manage-post"}})
	fs.Close()
	if err != nil || !posted.Accepted {
		t.Fatal(err)
	}
	for _, a := range []struct {
		login, role string
		permissions []string
	}{
		{"readerview", "moderator", []string{}},
		{"moderator", "moderator", []string{"evidence.manage"}},
		{"exportless", "board_admin", []string{"evidence.manage"}},
	} {
		if _, err = repo.CreateAdministrator(a.login, a.login, adminTestSecret, AdministratorAccess{Role: a.role, Boards: []domain.ID{board.ID}, Permissions: a.permissions, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		repo.Close()
		repo, err = OpenPostingRepository(cfg, postcapture.Validate)
		if err != nil {
			t.Fatal(err)
		}
	}
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/boards/%s/threads/%d/posts", board.ID, posted.Key)
	owner := newAdminClient(t, repo)
	defer owner.server.Close()
	if owner.login(adminTestSecret) != 303 || owner.reauth(adminTestSecret) != 200 {
		t.Fatal("owner login")
	}
	res, page := owner.request("GET", base+"/1", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "/inspect\"") {
		t.Fatal("implicit site admin evidence read")
	}
	public, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(public.Handler)
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL+base+"/1", nil)
	req.Host = "127.0.0.1:9080"
	pub, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, pub.Body)
	pub.Body.Close()
	if pub.StatusCode != 404 {
		t.Fatal("admin posts exposed publicly", pub.StatusCode)
	}
	for _, login := range []string{"readerview", "moderator", "exportless"} {
		// 役割ごとに認証管理を独立させ、共有IPの試行制限試験と混ぜない。
		repo.mu.Lock()
		repo.adminAuth = nil
		repo.mu.Unlock()
		c := newAdminClient(t, repo)
		_, loginPage := c.request("GET", "/login", "", nil)
		f := pageFields(loginPage)
		f.Set("login", login)
		f.Set("password", adminTestSecret)
		if res, _ := c.request("POST", "/login", f.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}); res.StatusCode != 303 {
			t.Fatal("limited login")
		}
		if c.reauth(adminTestSecret) != 200 {
			t.Fatal("limited reauth")
		}
		res, page = c.request("GET", base+"/1", "", nil)
		if login == "readerview" {
			if res.StatusCode != 200 || strings.Contains(page, "/inspect\"") {
				t.Fatal("moderator without records grant", res.StatusCode)
			}
			raw := c.cookies["oimo_admin"].Value
			session, e := repo.adminAuth.Lookup(raw, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			fields := url.Values{"csrf": {session.CSRF(base + "/1/inspect")}, "request_id": {domain.NewID().String()}, "related": {"post"}}
			if res, _ = c.request("POST", base+"/1/inspect", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}); res.StatusCode != 403 {
				t.Fatal("record permission bypass", res.StatusCode)
			}
			c.server.Close()
			continue
		}
		if res.StatusCode != 200 {
			t.Fatal("moderator mode", login, res.StatusCode)
		}
		if res, _ = c.request("GET", fmt.Sprintf("/boards/%s/threads/%d/posts/1", other.ID, posted.Key), "", nil); res.StatusCode != 403 {
			t.Fatal("board scope bypass")
		}
		fields := postManagementFields(t, page, base+"/1/inspect")
		fields.Set("related", "post")
		res, private := c.request("POST", base+"/1/inspect", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 200 {
			t.Fatal("limited evidence inspect", login, res.StatusCode)
		}
		if login == "moderator" && strings.Contains(private, base+"/1/rule") {
			t.Fatal("moderator gained board admin rule permission")
		}
		if !strings.Contains(private, base+"/1/export") {
			t.Fatal("combined record grant missing export")
		}
		// 統合権限で出力できても、一致しない選択集合では保全や出力を始めない。
		raw := c.cookies["oimo_admin"].Value
		session, err := repo.adminAuth.Lookup(raw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		export := url.Values{"csrf": {session.CSRF(base + "/1/export")}, "request_id": {domain.NewID().String()}, "related": {"post"}, "selection": {"untrusted"}}
		casesBefore, _ := repo.evidenceCases.Cases()
		res, _ = c.request("POST", base+"/1/export", export.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		casesAfter, _ := repo.evidenceCases.Cases()
		if res.StatusCode != 412 || len(casesAfter) != len(casesBefore) {
			t.Fatal("stale selection caused export side effect", login, res.StatusCode)
		}
		c.server.Close()
	}
}

func TestAdminPostsAnonymousSubjectPrefill(t *testing.T) {
	cfg, repo, board := anonymousAdminFixture(t, "required")
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	server, request, cookies := anonymousHTTP(t, repo, siteID(repo.site.State()))
	fields := url.Values{"bbs": {"news"}, "subject": {"匿名主体"}, "MESSAGE": {"SUBJECT-CONTENT"}, "oimo_request_id": {"manage-anon-create"}}
	for i := 0; i < 3; i++ {
		request("POST", "/test/bbs.cgi", fields)
	}
	token, err := repo.anonymous.verify(cookies["oimo_anon"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	subject := repo.anonymous.subject(token.ID)
	var thread uint64
	for key := range repo.posting[board].threads {
		thread = key
	}
	server.Close()
	if thread == 0 {
		t.Fatal("anonymous create")
	}
	if _, err = repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	base := fmt.Sprintf("/boards/%s/threads/%d/posts", board, thread)
	_, page := c.request("GET", base+"/1", "", nil)
	inspect := postManagementFields(t, page, base+"/1/inspect")
	inspect.Set("related", "post")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, private := c.request("POST", base+"/1/inspect", inspect.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(private, subject.String()) || strings.Contains(private, cookies["oimo_anon"].Value) {
		t.Fatal("anonymous identity projection", res.StatusCode)
	}
	related := postManagementFields(t, private, base+"/1/inspect")
	related.Set("related", "token")
	if res, _ = c.request("POST", base+"/1/inspect", related.Encode(), headers); res.StatusCode != 200 {
		t.Fatal("same subject selection")
	}
	rule := postManagementFields(t, private, base+"/1/rule")
	rule.Set("kind", "token")
	res, form := c.request("POST", base+"/1/rule", rule.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(form, `name="target" value="`+subject.String()+`"`) {
		t.Fatal("wrong HMAC selected", res.StatusCode)
	}
	// Prefilled existing HTML form registers a token restriction without copying or entering HMAC manually.
	path := "/boards/" + board.String() + "/rules"
	registration := postManagementFields(t, form, path)
	target := regexp.MustCompile(`<input name="target" value="([^"]*)"`).FindStringSubmatch(form)
	if len(target) != 2 {
		t.Fatal("target input")
	}
	registration.Set("target", html.UnescapeString(target[1]))
	for key, value := range map[string]string{"field": "token", "operator": "exact", "effect": "deny", "operation": "both", "reason_code": "abuse", "duration_minutes": "60", "extra_field": "none", "extra_operator": "exact", "extra_value": "", "allow_rule_ids": "", "refill_seconds": "", "burst": "", "window_limit": ""} {
		registration.Set(key, value)
	}
	registration.Set("line_target", "mobile")
	registration.Set("line_extra", "mobile")
	if res, _ = c.request("POST", path, registration.Encode(), headers); res.StatusCode != 303 {
		t.Fatal("source-derived token registration", res.StatusCode)
	}
	_, list := c.rules(board)
	if len(list.Rules) != 1 || list.Rules[0].Target != subject.String() || list.Rules[0].Match.Field != "token" {
		t.Fatal("token condition not persisted")
	}
}

func TestAdminPostsPaginationEscapingAndDeleteRevision(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "pagingmanage", "レスページ")
	if err != nil {
		t.Fatal(err)
	}
	fs := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer fs.Close()
	first, err := sendForm(fs, url.Values{"bbs": {"pagingmanage"}, "subject": {"ページ"}, "MESSAGE": {"<script>alert(1)</script>\n次の行"}, "oimo_request_id": {"manage-pages-first"}})
	if err != nil || !first.Accepted {
		t.Fatal(err)
	}
	for n := 2; n <= 51; n++ {
		post, err := sendForm(fs, url.Values{"bbs": {"pagingmanage"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {fmt.Sprintf("BODY-%03d", n)}, "oimo_request_id": {fmt.Sprintf("manage-pages-%04d", n)}})
		if err != nil || !post.Accepted {
			t.Fatal("pagination post", n, err)
		}
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("auth")
	}
	base := fmt.Sprintf("/boards/%s/threads/%d/posts", board.ID, first.Key)
	res, page := c.request("GET", base+"/1", "", nil)
	if res.StatusCode != 200 || strings.Count(page, `id="post-`) != 50 || strings.Contains(page, "BODY-051") || strings.Contains(page, "<script>alert(1)</script>") || !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;\n次の行") {
		t.Fatal("first page/XSS", res.StatusCode)
	}
	res, last := c.request("GET", base+"/51", "", nil)
	if res.StatusCode != 200 || strings.Count(last, `id="post-`) != 1 || !strings.Contains(last, "BODY-051") {
		t.Fatal("second page", res.StatusCode)
	}
	stale := postManagementFields(t, page, base+"/1/delete")
	stale.Set("confirm", "yes")
	posted, err := sendForm(fs, url.Values{"bbs": {"pagingmanage"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"CONCURRENT-RESPONSE"}, "oimo_request_id": {"manage-concurrent-post"}})
	if err != nil || !posted.Accepted {
		t.Fatal(err)
	}
	res, _ = c.request("POST", base+"/1/delete", stale.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 412 {
		t.Fatal("stale deletion applied", res.StatusCode)
	}
	if res, _ = c.request("GET", base+"/0", "", nil); res.StatusCode != 404 {
		t.Fatal("invalid response offset")
	}
}
