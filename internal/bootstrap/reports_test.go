// 実HTTPで依頼受付・照会・管理回答と、期限/改変/復元境界を検査する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
)

type reportTestClient struct {
	server *httptest.Server
	cookie *http.Cookie
	token  string
	t      *testing.T
}

func newReportTestClient(t *testing.T, repo *Repository) *reportTestClient {
	t.Helper()
	observer, e := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "reports-test")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	c := &reportTestClient{server: server, t: t}
	status, body := c.request("GET", "/reports", nil)
	if status != 200 {
		t.Fatal(status, body)
	}
	c.token = pageFields(body).Get("csrf")
	if c.token == "" || c.cookie == nil {
		t.Fatal(body)
	}
	return c
}
func (c *reportTestClient) request(method, path string, fields url.Values) (int, string) {
	c.t.Helper()
	req, e := http.NewRequest(method, c.server.URL+path, strings.NewReader(fields.Encode()))
	if e != nil {
		c.t.Fatal(e)
	}
	req.Host = "127.0.0.1:9080"
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	if method == "POST" {
		req.Header.Set("Origin", "http://127.0.0.1:9080")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, e := c.server.Client().Do(req)
	if e != nil {
		c.t.Fatal(e)
	}
	defer res.Body.Close()
	for _, cookie := range res.Cookies() {
		if cookie.Name == "oimo_reports" {
			c.cookie = cookie
		}
	}
	raw, e := io.ReadAll(res.Body)
	if e != nil {
		c.t.Fatal(e)
	}
	return res.StatusCode, string(raw)
}
func reportTestSetup(t *testing.T) (Config, *Repository, *reportTestClient, domain.ID, string) {
	t.Helper()
	cfg, repo := adminFixture(t)
	if _, e := repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"private_reports.read"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	repo = reopenPrivilegeFixture(t, cfg, repo)
	board, e := repo.CreateBoard(t.Context(), "reports", "依頼対象")
	if e != nil {
		t.Fatal(e)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	posted, e := sendForm(form, url.Values{"bbs": {"reports"}, "subject": {"依頼対象"}, "MESSAGE": {"投稿本文は依頼へ複製しない"}, "oimo_request_id": {"report-thread-0001"}})
	if e != nil || !posted.Accepted {
		t.Fatal(posted, e)
	}
	return cfg, repo, newReportTestClient(t, repo), board.ID, strconv.FormatUint(posted.Key, 10)
}
func createTestReport(t *testing.T, c *reportTestClient, key string) (domain.ID, string) {
	t.Helper()
	fields := url.Values{"csrf": {c.token}, "board": {"reports"}, "thread": {key}, "ranges": {"1"}, "category": {"normal"}, "reason": {"非公開の依頼理由<script>bad</script>"}, "contact": {"非公開連絡先"}}
	status, body := c.request("POST", "/reports", fields)
	if status != 201 {
		t.Fatal(status, body)
	}
	match := regexp.MustCompile(`依頼ID：<code>([^<]+)</code>`).FindStringSubmatch(body)
	secret := regexp.MustCompile(`照会秘密：<code>([^<]+)</code>`).FindStringSubmatch(body)
	if len(match) != 2 || len(secret) != 2 {
		t.Fatal(body)
	}
	id, e := parseReportID(match[1])
	if e != nil {
		t.Fatal(e)
	}
	return id, secret[1]
}

func TestDeletionReportsHTTPAndRestart(t *testing.T) {
	cfg, repo, c, _, key := reportTestSetup(t)
	defer func() {
		c.server.Close()
		if repo != nil {
			repo.Close()
		}
	}()
	id, secret := createTestReport(t, c, key)
	lookup := url.Values{"csrf": {c.token}, "id": {id.String()}, "secret": {secret}}
	status, body := c.request("POST", "/reports/lookup", lookup)
	if status != 200 || !strings.Contains(body, "open") || strings.Contains(body, "非公開連絡先") {
		t.Fatal(status, body)
	}
	wrong := url.Values{}
	for k, v := range lookup {
		wrong[k] = append([]string{}, v...)
	}
	wrong.Set("secret", strings.Repeat("A", 43))
	wrongStatus, wrongBody := c.request("POST", "/reports/lookup", wrong)
	wrong.Set("id", domain.NewID().String())
	missingStatus, missingBody := c.request("POST", "/reports/lookup", wrong)
	if wrongStatus != 404 || missingStatus != 404 || wrongBody != missingBody {
		t.Fatal(wrongStatus, missingStatus, wrongBody, missingBody)
	}
	admin := newAdminClient(t, repo)
	defer admin.server.Close()
	admin.login(adminTestSecret)
	res, body := admin.request("GET", "/api/v1/reports", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "非公開連絡先") || strings.Contains(body, "source_ip") || strings.Contains(body, "lookup_secret") || strings.Contains(body, secret) {
		t.Fatal(res.StatusCode, body)
	}
	path := "/reports/" + id.String()
	res, body = admin.request("GET", path, "", nil)
	if res.StatusCode != 200 || strings.Contains(body, "<script>bad</script>") {
		t.Fatal(res.StatusCode, body)
	}
	fields := pageFields(body)
	fields.Set("state", "resolved")
	fields.Set("answer", "依頼を確認しました。")
	fields.Set("duplicate_of", "")
	res, body = admin.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal(res.StatusCode, body)
	}
	res, body = admin.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 409 {
		t.Fatal(res.StatusCode, body)
	}
	status, body = c.request("POST", "/reports/lookup", lookup)
	if status != 200 || !strings.Contains(body, "依頼を確認しました。") || !strings.Contains(body, "resolved") {
		t.Fatal(status, body)
	}
	raw, e := os.ReadFile(filepath.Join(cfg.DataDir, "reports", reportDirectory, id.String()+".json"))
	if e != nil || strings.Contains(string(raw), secret) || strings.Contains(string(raw), "投稿本文は依頼へ複製しない") {
		t.Fatal(string(raw), e)
	}
	c.server.Close()
	admin.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	c = newReportTestClient(t, repo)
	lookup.Set("csrf", c.token)
	status, body = c.request("POST", "/reports/lookup", lookup)
	if status != 200 || !strings.Contains(body, "依頼を確認しました。") {
		t.Fatal(status, body)
	}
}

func TestDeletionReportExpiryAndTamper(t *testing.T) {
	cfg, repo, c, _, key := reportTestSetup(t)
	id, _ := createTestReport(t, c, key)
	c.server.Close()
	secret, e := reportKey(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	record, e := readReport(cfg.DataDir, id, secret)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(0, int64(record.Expires))
	if e = repo.sweepReports(now); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(cfg.DataDir, "reports", reportDirectory, id.String()+".json")); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	if e = repo.sweepReports(now.Add(-time.Second)); e == nil {
		t.Fatal("reversed cleanup accepted")
	}
	repo.Close()
	// 別のfixtureで署名の無い私情報変更を起動前に拒否する。
	cfg, repo, c, _, key = reportTestSetup(t)
	id, _ = createTestReport(t, c, key)
	c.server.Close()
	repo.Close()
	file := filepath.Join(cfg.DataDir, "reports", reportDirectory, id.String()+".json")
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	var envelope reportEnvelope
	if e = json.Unmarshal(raw, &envelope); e != nil {
		t.Fatal(e)
	}
	envelope.Value.Answer = "改変された回答"
	raw, _ = json.Marshal(envelope)
	if e = os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if opened, e := OpenPostingRepository(cfg, postcapture.Validate); e == nil {
		opened.Close()
		t.Fatal("tampered report opened")
	}
}

func TestDeletionReportBackupOmissionIsExplicit(t *testing.T) {
	cfg, repo, c, _, key := reportTestSetup(t)
	id, secret := createTestReport(t, c, key)
	c.server.Close()
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(parent, "backup")
	captured, e := CaptureOfflineBackup(t.Context(), cfg, output)
	if e != nil || !captured.Verified || !captured.DeletionReportsOmitted {
		t.Fatal(captured, e)
	}
	raw, e := os.ReadFile(filepath.Join(output, "manifest.json"))
	if e != nil || !strings.Contains(string(raw), `"deletion_reports_omitted":true`) || strings.Contains(string(raw), secret) {
		t.Fatal(string(raw), e)
	}
	if e := filepath.WalkDir(output, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !entry.IsDir() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if strings.Contains(string(raw), "非公開連絡先") || strings.Contains(string(raw), secret) {
				t.Fatalf("private report leaked into backup: %s", path)
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	keys := filepath.Join(parent, "keys")
	if _, e = ExportBackupKeys(t.Context(), cfg, output, keys); e != nil {
		t.Fatal(e)
	}
	work := filepath.Join(parent, "work")
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	replay, e := VerifyBackupReplay(t.Context(), output, keys, work)
	if e != nil || !replay.Replayed || replay.RestoreReady || !replay.DeletionReportsOmitted {
		t.Fatal(replay, e)
	}
	// 実正本の依頼は通常backup/replayで変更されない。
	signing, e := reportKey(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	saved, e := readReport(cfg.DataDir, id, signing)
	if e != nil || !reportSecretMatches(saved, secret) {
		t.Fatal(saved, e)
	}
}

func TestDeletionReportRateAndReopenDeadline(t *testing.T) {
	cfg, repo, c, _, key := reportTestSetup(t)
	defer repo.Close()
	defer c.server.Close()
	id, _ := createTestReport(t, c, key)
	admin := newAdminClient(t, repo)
	defer admin.server.Close()
	admin.login(adminTestSecret)
	session, e := repo.adminAuth.Lookup(admin.cookies["oimo_admin"].Value, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	path := "/reports/" + id.String()
	if e = repo.updateReport(session, path, "1", "resolved", "対応済み", ""); e != nil {
		t.Fatal(e)
	}
	signing, e := reportKey(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	resolved, e := readReport(cfg.DataDir, id, signing)
	if e != nil {
		t.Fatal(e)
	}
	if e = repo.updateReport(session, path, "2", "in_progress", "再確認", ""); e != nil {
		t.Fatal(e)
	}
	reopened, e := readReport(cfg.DataDir, id, signing)
	if e != nil || reopened.Expires != resolved.Expires || reopened.Resolved == nil || *reopened.Resolved != *resolved.Resolved {
		t.Fatal(reopened, e)
	}
	req := httptest.NewRequest("POST", "http://127.0.0.1:9080/reports/lookup", nil)
	req.RemoteAddr = "192.0.2.30:1234"
	repo.mu.Lock()
	defer repo.mu.Unlock()
	for range 10 {
		if e := repo.reportRate(req, true, signing); e != nil {
			t.Fatal(e)
		}
	}
	if e := repo.reportRate(req, true, signing); e == nil {
		t.Fatal("11th lookup accepted")
	}
	for key := range repo.reportRates {
		if strings.Contains(key, "192.0.2.") {
			t.Fatal("rate index stores raw IP")
		}
	}
}

func TestDeletionReportScopeDoesNotExposePrivateInput(t *testing.T) {
	cfg, repo, c, _, key := reportTestSetup(t)
	id, _ := createTestReport(t, c, key)
	c.server.Close()
	other, e := repo.CreateBoard(t.Context(), "otherreport", "別担当")
	if e != nil {
		t.Fatal(e)
	}
	account, e := repo.CreateAdministrator("other.report", "別担当", adminTestSecret, AdministratorAccess{Role: "moderator", Boards: []domain.ID{other.ID}, Permissions: []string{"private_reports.read"}, Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	if _, e := repo.AdminHTTPServer(); e != nil {
		t.Fatal(e)
	}
	_, session, sessionErr := repo.adminAuth.Create(account.ID, account.Generation, time.Now())
	if sessionErr != nil {
		t.Fatal(sessionErr)
	}
	page, e := repo.adminReports(session, "/reports", "")
	if e != nil || len(page.Reports) != 0 {
		t.Fatal(page, e)
	}
	path := "/reports/" + id.String()
	page, e = repo.adminReports(session, path, "")
	var denied *adminFailure
	if !errors.As(e, &denied) || denied.status != 403 || page.Report != nil {
		t.Fatal(page, e)
	}
	if e = repo.updateReport(session, path, "1", "resolved", "権限外回答", ""); !errors.As(e, &denied) || denied.status != 403 {
		t.Fatal(e)
	}
}
