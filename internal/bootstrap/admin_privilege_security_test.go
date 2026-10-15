// 管理HTTPの役割・担当板・追加権限を、再認証後も越えられないことを検査する。
package bootstrap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestAdminHTTPPrivilegeBoundaries(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "privilege", "担当板")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "outsideprivilege", "担当外")
	if err != nil {
		t.Fatal(err)
	}
	accounts := map[string]AdministratorInfo{}
	for _, role := range []string{"moderator", "board_admin", "site_admin"} {
		boards := []domain.ID{board.ID}
		if role == "site_admin" {
			boards = []domain.ID{}
		}
		account, err := repo.CreateAdministrator("matrix."+role, "検査", adminTestSecret, AdministratorAccess{Role: role, Boards: boards, Permissions: []string{}, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		accounts[role] = account
		repo = reopenPrivilegeFixture(t, cfg, repo)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	for _, role := range []string{"moderator", "board_admin", "site_admin"} {
		t.Run(role, func(t *testing.T) {
			account := accounts[role]
			cookie, session, err := repo.adminAuth.Create(account.ID, account.Generation, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			c.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: cookie}
			if c.reauth(adminTestSecret) != 200 {
				t.Fatal("reauthentication must be available to every role")
			}
			session, err = repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			before := repo.site.State().Seq
			for _, prefix := range []string{"", "/api/v1"} {
				if role != "site_admin" {
					for _, path := range []string{"/", "/site", "/board-categories", "/admin-access", "/administrators", "/administrators/" + account.ID.String(), "/operations", "/anonymous", "/abuse-guard", "/maintenance", "/maintenance/emergency-reserve", "/reading", "/networks"} {
						for _, method := range []string{"GET", "POST", "PATCH"} {
							res, body := c.request(method, prefix+path, "{}", http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {session.CSRF(prefix + path)}})
							if res.StatusCode != 403 || (prefix != "" && !strings.Contains(body, "PERMISSION_DENIED")) {
								t.Fatalf("%s %s: %d %s", method, prefix+path, res.StatusCode, body)
							}
						}
					}
					for _, owner := range []domain.ID{other.ID, domain.NewID()} {
						for _, suffix := range []string{"settings", "thread-settings", "local-rules", "rules", "threads/1/actions", "threads/1/moderation", "threads/1/posts/1"} {
							for _, method := range []string{"GET", "POST", "PATCH"} {
								path := fmt.Sprintf("%s/boards/%s/%s", prefix, owner, suffix)
								res, _ := c.request(method, path, "{}", http.Header{"Content-Type": {"application/json"}})
								if res.StatusCode != 403 {
									t.Fatalf("outside scope: %s %s: %d", method, path, res.StatusCode)
								}
							}
						}
					}
				}
				for _, suffix := range []string{"settings", "thread-settings", "local-rules", "rules"} {
					if adminRoleRank[role] >= adminRoleRank["board_admin"] {
						continue
					}
					path := fmt.Sprintf("%s/boards/%s/%s", prefix, board.ID, suffix)
					for _, method := range []string{"GET", "POST", "PATCH"} {
						res, body := c.request(method, path, "{}", http.Header{"Content-Type": {"application/json"}})
						if res.StatusCode != 403 || (prefix != "" && !strings.Contains(body, "PERMISSION_DENIED")) {
							t.Fatalf("role write: %s %s: %d %s", method, path, res.StatusCode, body)
						}
					}
				}
				if role == "moderator" {
					for _, path := range []string{"/boards", "/audit?board_id=" + board.ID.String(), "/boards/" + board.ID.String() + "/threads"} {
						res, _ := c.request("GET", prefix+path, "", nil)
						if res.StatusCode != 403 {
							t.Fatalf("restricted read %s: %d", prefix+path, res.StatusCode)
						}
					}
					for _, path := range []string{"/reports", "/reports/" + domain.NewID().String()} {
						res, body := c.request("GET", prefix+path, "", nil)
						if res.StatusCode != 403 || strings.Contains(body, "非公開連絡先") {
							t.Fatalf("private reports: %d %s", res.StatusCode, body)
						}
					}
					res, _ := c.request("GET", prefix+"/evidence", "", nil)
					if res.StatusCode != 403 {
						t.Fatal("implicit evidence permission", res.StatusCode)
					}
				}
			}
			if repo.site.State().Seq != before {
				t.Fatal("rejected request changed durable state")
			}
		})
	}
}

func TestPrivateReportsRequireExplicitPermission(t *testing.T) {
	cfg, repo, public, board, key := reportTestSetup(t)
	defer func() { repo.Close() }()
	defer public.server.Close()
	id, _ := createTestReport(t, public, key)
	public.server.Close()
	accounts := map[string]AdministratorInfo{}
	for _, role := range []string{"moderator", "board_admin", "site_admin"} {
		boards := []domain.ID{board}
		if role == "site_admin" {
			boards = []domain.ID{}
		}
		for _, grant := range []bool{false, true} {
			permissions := []string{}
			if grant {
				permissions = append(permissions, "private_reports.read")
			}
			login := fmt.Sprintf("private.%s.%t", role, grant)
			a, err := repo.CreateAdministrator(login, "通報検査", adminTestSecret, AdministratorAccess{Role: role, Boards: boards, Permissions: permissions, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			accounts[login] = a
			repo = reopenPrivilegeFixture(t, cfg, repo)
		}
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	signing, err := reportKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signing[:])
	for _, role := range []string{"moderator", "board_admin", "site_admin"} {
		for _, grant := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", role, grant), func(t *testing.T) {
				a := accounts[fmt.Sprintf("private.%s.%t", role, grant)]
				cookie, session, err := repo.adminAuth.Create(a.ID, a.Generation, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				c.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: cookie}
				allowed := grant || role != "moderator"
				for _, path := range []string{"/reports", "/reports/" + id.String(), "/api/v1/reports", "/api/v1/reports/" + id.String()} {
					res, body := c.request("GET", path, "", nil)
					if allowed {
						if res.StatusCode != 200 || (path != "/reports" && !strings.Contains(body, "非公開連絡先")) {
							t.Fatalf("permitted read: %d %s", res.StatusCode, body)
						}
					} else if res.StatusCode != 403 || strings.Contains(body, "非公開連絡先") {
						t.Fatalf("private leak: %d %s", res.StatusCode, body)
					}
				}
				if !allowed {
					before := repo.site.State().Seq
					path := "/reports/" + id.String()
					fields := url.Values{"csrf": {session.CSRF(path)}, "revision": {"1"}, "state": {"resolved"}, "answer": {"拒否される回答"}, "duplicate_of": {""}}
					res, _ := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
					if res.StatusCode != 403 {
						t.Fatal("unauthorized HTTP answer", res.StatusCode)
					}
					if err := repo.updateReport(session, "/reports/"+id.String(), "1", "resolved", "拒否される回答", ""); err == nil {
						t.Fatal("unauthorized answer saved")
					}
					saved, err := readReport(cfg.DataDir, id, signing)
					if err != nil || saved.Revision != 1 || repo.site.State().Seq != before {
						t.Fatal("denied update changed report", err)
					}
				}
			})
		}
	}
}

// reopenPrivilegeFixture は停止中CLIのアカウント変更後に現在の認可状態を再読込する。
func reopenPrivilegeFixture(t *testing.T, cfg Config, repo *Repository) *Repository {
	t.Helper()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

// logoutReportWriter はヘッダー確定と本文送信の間のログアウトを明示的に再現する。
type logoutReportWriter struct {
	*httptest.ResponseRecorder
	logout func()
}

func (w *logoutReportWriter) WriteHeader(status int) {
	w.ResponseRecorder.WriteHeader(status)
	w.logout()
}

func TestPrivateReportSendRechecksSession(t *testing.T) {
	_, repo, public, _, key := reportTestSetup(t)
	defer repo.Close()
	defer public.server.Close()
	createTestReport(t, public, key)
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	server, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	cookie := c.cookies["oimo_admin"]
	req := httptest.NewRequest("GET", c.origin+"/api/v1/reports", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	writer := &logoutReportWriter{recorder, func() { repo.adminAuth.Delete(cookie.Value) }}
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("private report send must abort after logout")
			}
		}()
		server.Handler.ServeHTTP(writer, req)
	}()
	if recorder.Body.Len() != 0 {
		t.Fatal("private report sent after logout")
	}
}

// TestModeratorExtraPermissionsDoNotGrantAdministrativeReads は追加権限と再認証で閲覧制限を迂回できないことを検査する。
func TestModeratorExtraPermissionsDoNotGrantAdministrativeReads(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "restricted", "閲覧制限検査")
	if err != nil {
		t.Fatal(err)
	}
	account, err := repo.CreateAdministrator("restricted.moderator", "管理担当", adminTestSecret, AdministratorAccess{Role: "moderator", Boards: []domain.ID{board.ID}, Permissions: []string{"private_reports.read", "evidence.manage"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	repo = reopenPrivilegeFixture(t, cfg, repo)
	c := newAdminClient(t, repo)
	defer c.server.Close()
	cookie, _, err := repo.adminAuth.Create(account.ID, account.Generation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: cookie}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	for _, prefix := range []string{"", "/api/v1"} {
		for _, path := range []string{"/boards", "/audit?board_id=" + board.ID.String(), "/boards/" + board.ID.String() + "/settings", "/boards/" + board.ID.String() + "/threads"} {
			res, body := c.request("GET", prefix+path, "", nil)
			if res.StatusCode != 403 || strings.Contains(body, "閲覧制限検査") {
				t.Fatalf("restricted read: %s %d", prefix+path, res.StatusCode)
			}
		}
	}
	session, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.adminBoardSettings(t.Context(), session, board.ID); err == nil {
		t.Fatal("repository settings read allowed")
	}
	repo.mu.Lock()
	err = repo.authorizeAuditBoards(session, auditQuery{Board: board.ID})
	repo.mu.Unlock()
	if err == nil {
		t.Fatal("repository audit read allowed")
	}
}
