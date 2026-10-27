// 更新の確認画面・役割・再認証・CSRF・世代失効と、停止前の監査保存を実HTTPで検査する。
package bootstrap

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/selfupdate"
)

type updateAgentFixture struct {
	mu              sync.Mutex
	state           selfupdate.State
	checks, applies int
	onStatus        func()
}

func startUpdateAgentFixture(t *testing.T) *updateAgentFixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "oimo-update-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "control.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	a := &updateAgentFixture{state: selfupdate.State{Phase: "idle", CurrentRevision: strings.Repeat("a", 40)}}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		switch r.URL.Path {
		case "/status":
			if a.onStatus != nil {
				a.onStatus()
				a.onStatus = nil
			}
		case "/check":
			a.checks++
			a.state.Phase, a.state.LatestRevision, a.state.Token = "ready", strings.Repeat("b", 40), strings.Repeat("c", 64)
			a.state.Expires = time.Now().Add(30 * time.Minute)
		case "/apply":
			var in struct{ Token, Revision string }
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.Token != a.state.Token || in.Revision != a.state.LatestRevision {
				w.WriteHeader(409)
				return
			}
			if a.state.Phase == "ready" {
				a.applies++
				a.state.Phase = "preparing"
			}
		default:
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(a.state)
	})}
	go server.Serve(l)
	t.Cleanup(func() { server.Close() })
	t.Setenv("OIMO_UPDATE_SOCKET", socket)
	return a
}

func TestSoftwareUpdateConfirmationAndAudit(t *testing.T) {
	a := startUpdateAgentFixture(t)
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if res, _ := c.request("GET", "/updates", "", nil); res.StatusCode != 401 {
		t.Fatal("anonymous update page", res.StatusCode)
	}
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, page := c.request("GET", "/updates", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "最新版を確認する") {
		t.Fatal(res.StatusCode, page)
	}
	fields := pageFields(page)
	formHeader := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, _ = c.request("POST", "/updates/check", fields.Encode(), formHeader)
	if res.StatusCode != 303 {
		t.Fatal("check", res.StatusCode)
	}
	res, page = c.request("GET", "/updates/confirm", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "一時停止して再起動") || strings.Contains(page, `action="/updates/apply"`) {
		t.Fatal("missing reauthentication", res.StatusCode, page)
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	res, page = c.request("GET", "/updates/confirm", "", nil)
	fields = pageFields(page)
	if res.StatusCode != 200 || fields.Get("revision") != strings.Repeat("b", 40) || !strings.Contains(page, `name="restart_confirmed"`) {
		t.Fatal("confirmation", res.StatusCode, page)
	}
	fields.Set("restart_confirmed", "yes")
	valid := fields.Encode()
	fields.Set("csrf", "forged")
	if res, _ := c.request("POST", "/updates/apply", fields.Encode(), formHeader); res.StatusCode != 403 {
		t.Fatal("CSRF", res.StatusCode)
	}
	fields = pageFields(page)
	if res, _ := c.request("POST", "/updates/apply", fields.Encode(), formHeader); res.StatusCode != 400 {
		t.Fatal("unchecked confirmation", res.StatusCode)
	}
	fields.Set("restart_confirmed", "yes")
	fields.Set("revision", strings.Repeat("d", 40))
	if res, _ := c.request("POST", "/updates/apply", fields.Encode(), formHeader); res.StatusCode != 409 {
		t.Fatal("changed revision", res.StatusCode)
	}
	if res, _ := c.request("POST", "/updates/apply", valid, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {"https://evil.example"}}); res.StatusCode != 403 {
		t.Fatal("Origin", res.StatusCode)
	}
	for range 2 {
		res, body := c.request("POST", "/updates/apply", valid, formHeader)
		if res.StatusCode != 303 {
			t.Fatal("apply", res.StatusCode, body)
		}
	}
	a.mu.Lock()
	checks, applies := a.checks, a.applies
	a.mu.Unlock()
	if checks != 1 || applies != 1 {
		t.Fatal("duplicate dispatch", checks, applies)
	}
	res, body := c.request("GET", "/api/v1/audit", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "software_update_request") {
		t.Fatal("audit", res.StatusCode, body)
	}
	if controlCollectionCount(repo.site.State(), "admin_receipt") != 1 {
		t.Fatal("duplicate audit receipts")
	}
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("reopen after update request", err)
	}
	if controlCollectionCount(repo.site.State(), "admin_receipt") != 1 {
		t.Fatal("receipt lost")
	}
}

func TestSoftwareUpdateRejectsLowerRoles(t *testing.T) {
	for _, role := range []string{"moderator", "board_admin"} {
		t.Run(role, func(t *testing.T) {
			a := startUpdateAgentFixture(t)
			cfg, repo := adminFixture(t)
			defer func() { repo.Close() }()
			account, err := repo.CreateAdministrator("update.limited", "担当者", adminTestSecret, AdministratorAccess{Role: role, Boards: []domain.ID{}, Permissions: []string{}, Enabled: true})
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
			for _, path := range []string{"/updates", "/updates/confirm", "/updates/check", "/updates/apply"} {
				method := "GET"
				if strings.HasSuffix(path, "check") || strings.HasSuffix(path, "apply") {
					method = "POST"
				}
				res, body := c.request(method, path, "", nil)
				if res.StatusCode != 403 || strings.Contains(body, strings.Repeat("a", 40)) {
					t.Fatal("lower role", path, res.StatusCode)
				}
			}
			res, body := c.request("GET", "/manual", "", nil)
			if res.StatusCode != 200 || strings.Contains(body, `href="/updates"`) {
				t.Fatal("menu leaked", res.StatusCode)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.checks != 0 || a.applies != 0 {
				t.Fatal("forbidden helper request")
			}
		})
	}
}

func TestSoftwareUpdateDisabledAndRevokedSession(t *testing.T) {
	t.Run("expired-reauthentication", func(t *testing.T) {
		a := startUpdateAgentFixture(t)
		_, repo := adminFixture(t)
		defer repo.Close()
		c := newAdminClient(t, repo)
		defer c.server.Close()
		if c.login(adminTestSecret) != 303 {
			t.Fatal("login")
		}
		s, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		raw := expiredReauthCookie(t, repo, s)
		s, err = repo.adminAuth.Lookup(raw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		c.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: raw}
		a.mu.Lock()
		a.state.Phase, a.state.Token, a.state.LatestRevision = "ready", strings.Repeat("c", 64), strings.Repeat("b", 40)
		a.state.Expires = time.Now().Add(time.Minute)
		a.mu.Unlock()
		fields := url.Values{"csrf": {s.CSRF("/updates/apply")}, "token": {strings.Repeat("c", 64)}, "revision": {strings.Repeat("b", 40)}, "restart_confirmed": {"yes"}}
		res, body := c.request("POST", "/updates/apply", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 403 || !strings.Contains(body, "再認証") || !strings.Contains(body, "%2Fupdates") {
			t.Fatal("expired reauthentication", res.StatusCode)
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.applies != 0 || controlCollectionCount(repo.site.State(), "admin_receipt") != 0 {
			t.Fatal("expired reauthentication mutated state")
		}
	})
	t.Run("disabled", func(t *testing.T) {
		t.Setenv("OIMO_UPDATE_SOCKET", "")
		_, repo := adminFixture(t)
		defer repo.Close()
		c := newAdminClient(t, repo)
		defer c.server.Close()
		if c.login(adminTestSecret) != 303 {
			t.Fatal("login")
		}
		res, body := c.request("GET", "/updates", "", nil)
		if res.StatusCode != 200 || !strings.Contains(body, "未設定") || strings.Contains(body, `action="/updates/check"`) {
			t.Fatal(res.StatusCode, body)
		}
	})
	t.Run("revoked-before-dispatch", func(t *testing.T) {
		a := startUpdateAgentFixture(t)
		_, repo := adminFixture(t)
		defer repo.Close()
		c := newAdminClient(t, repo)
		defer c.server.Close()
		if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
			t.Fatal("login")
		}
		_, page := c.request("GET", "/updates", "", nil)
		res, _ := c.request("POST", "/updates/check", pageFields(page).Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 303 {
			t.Fatal(res.StatusCode)
		}
		_, page = c.request("GET", "/updates/confirm", "", nil)
		fields := pageFields(page)
		fields.Set("restart_confirmed", "yes")
		cookie := c.cookies["oimo_admin"].Value
		a.mu.Lock()
		a.onStatus = func() { repo.adminAuth.Delete(cookie) }
		a.mu.Unlock()
		res, _ = c.request("POST", "/updates/apply", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 401 {
			t.Fatal("revoked session dispatched", res.StatusCode)
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.applies != 0 {
			t.Fatal("revoked dispatch")
		}
	})
}

// TestSoftwareUpdateBrowser は確認・キャンセル・再認証・同意・受付を実ブラウザーで操作する。
func TestSoftwareUpdateBrowser(t *testing.T) {
	if os.Getenv("OIMO_BROWSER_NODE") == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMで有効化")
	}
	a := startUpdateAgentFixture(t)
	runAdminLayoutBrowser(t, "test-software-update-browser.mjs")
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.checks != 1 || a.applies != 1 {
		t.Fatal("browser dispatch count", a.checks, a.applies)
	}
}
