package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestAdminBoardCreateHTMLAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := c.request("GET", "/boards/new", "", nil)
	fields := url.Values{"key": {"newboard"}, "name": {"新しい板"}, "csrf": {pageFields(body).Get("csrf")}}
	res, body = c.request("POST", "/boards", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 403 || !strings.Contains(body, "再認証") {
		t.Fatal("missing reauthentication", res.StatusCode)
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauthentication")
	}
	res, body = c.request("GET", "/boards/new", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "板を追加") {
		t.Fatal("create form", body)
	}
	fields = pageFields(body)
	fields.Set("key", "newboard")
	fields.Set("name", "新しい板")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, body = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("create", res.StatusCode, body)
	}
	location := res.Header.Get("Location")
	res, audit, _ := c.audit("action=board_provisioning")
	if res.StatusCode != 200 || len(audit.Entries) != 1 || audit.Entries[0].ActorKind != "admin" || audit.Entries[0].ActorID == nil {
		t.Fatal("creator audit", res.StatusCode, audit)
	}

	boards, e := repo.Boards()
	if e != nil || len(boards) != 1 {
		t.Fatal(boards, e)
	}
	info := boards[0]
	if location != "/boards/"+info.ID.String()+"/settings" {
		t.Fatal(location)
	}
	res, _ = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 303 || res.Header.Get("Location") != location {
		t.Fatal("retry", res.StatusCode)
	}
	fields.Set("name", "違う名前")
	res, _ = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 409 {
		t.Fatal("key conflict", res.StatusCode)
	}
	fields.Set("key", "invalid-key")
	res, body = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 400 || !strings.Contains(body, "invalid-key") {
		t.Fatal("invalid input", res.StatusCode, body)
	}
	fields.Set("key", "otherboard")
	fields.Set("csrf", "wrong")
	res, _ = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 403 {
		t.Fatal("csrf", res.StatusCode)
	}
	public, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+"/bbsmenu.html", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/newboard/") {
		t.Fatal("menu", w.Code, w.Body.String())
	}
	form := formServer(t, repo, siteID(repo.site.State()), info.ID)
	accepted, e := sendForm(form, url.Values{"bbs": {"newboard"}, "subject": {"first"}, "MESSAGE": {"first"}, "oimo_request_id": {"new-board-post-00001"}})
	form.Close()
	if e != nil || !accepted.Accepted {
		t.Fatal("new board posting", accepted, e)
	}
	c.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := repo.CreateBoard(context.Background(), "newboard", "新しい板")
	if e != nil || recovered.ID != info.ID {
		t.Fatal("recovery", recovered, e)
	}
	repo.mu.Lock()
	entries, e := inspectBoardsMode(cfg, repo.site.State(), false, true)
	repo.mu.Unlock()
	if e != nil || len(entries) != 1 || entries[0].job.OwnerAdmin == nil {
		t.Fatal("creator lost", entries, e)
	}
}

func TestAdminBoardCreateRequiresSiteAdministrator(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	_, e := repo.CreateAdministrator("boardowner", "板担当", adminTestSecret, AdministratorAccess{Role: "board_admin", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true})
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
	c := newAdminClient(t, repo)
	defer c.server.Close()
	fields := url.Values{"key": {"forbidden"}, "name": {"権限外"}, "csrf": {"invalid"}}
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, _ := c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 401 {
		t.Fatal("anonymous", res.StatusCode)
	}
	_, body := c.request("GET", "/login", "", nil)
	login := pageFields(body)
	login.Set("login", "boardowner")
	login.Set("password", adminTestSecret)
	res, _ = c.request("POST", "/login", login.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("login", res.StatusCode)
	}
	res, body = c.request("GET", "/boards", "", nil)
	if res.StatusCode != 200 || strings.Contains(body, "板を追加") {
		t.Fatal("form exposed", res.StatusCode, body)
	}
	res, _ = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 403 {
		t.Fatal("board administrator", res.StatusCode)
	}
	boards, e := repo.Boards()
	if e != nil || len(boards) != 0 {
		t.Fatal("unauthorized mutation", boards, e)
	}
}

// TestAdminBoardCreateCrash は操作者付きjobの保存直後と公開直後から同じ板を復旧する。
func TestAdminBoardCreateCrash(t *testing.T) {
	for _, tc := range []struct{ stage, policy string }{{"job", ""}, {"active", ""}, {"job", "cap_only"}, {"active", "cap_only"}} {
		t.Run(tc.stage+"/"+tc.policy, func(t *testing.T) {
			stage := tc.stage
			cfg, repo := adminFixture(t)
			repo.mu.Lock()
			accounts, e := repo.administrators()
			repo.mu.Unlock()
			if e != nil || len(accounts) != 1 {
				t.Fatal(accounts, e)
			}
			owner := accounts[0].ID
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			raw, e := json.Marshal(cfg)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(filepath.Dir(cfg.DataDir), "admin-board-crash.json")
			mustWrite(t, path, raw)
			cmd := exec.Command(os.Args[0], "-test.run=^TestBoardProvisionCrash$")
			cmd.Env = append(os.Environ(), "OIMO_TEST_BOARD_CONFIG="+path, "OIMO_TEST_BOARD_STOP="+stage, "OIMO_TEST_BOARD_ADMIN="+owner.String(), "OIMO_TEST_BOARD_POLICY="+tc.policy)
			output, e := cmd.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok {
				t.Fatalf("child %v: %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("child not killed: %v %s", e, output)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			defer repo.Close()
			info, e := repo.CreateBoard(context.Background(), "persistent", "停止点の板")
			if e != nil {
				t.Fatal(e)
			}
			boards, e := repo.Boards()
			if e != nil || len(boards) != 1 || boards[0].ID != info.ID {
				t.Fatal(boards, e)
			}
			repo.mu.Lock()
			entries, e := inspectBoardsMode(cfg, repo.site.State(), false, true)
			repo.mu.Unlock()
			if e != nil || len(entries) != 1 || entries[0].job.OwnerAdmin == nil || *entries[0].job.OwnerAdmin != owner {
				t.Fatal("owner recovery", entries, e)
			}
			if tc.policy == "cap_only" {
				client := newAdminClient(t, repo)
				defer client.server.Close()
				if client.login(adminTestSecret) != 303 {
					t.Fatal("recovered login")
				}
				_, settings := client.board(info.ID.String())
				if settings.Settings.Create != "cap_only" || settings.Settings.Reply != "cap_only" {
					t.Fatal("crash lost CAP restrictions")
				}
			}
		})
	}
}

// TestAdminBoardCreateDuringPosting は既存板への投稿中に新板を追加できることを確認する。
func TestAdminBoardCreateDuringPosting(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, e := repo.CreateBoard(context.Background(), "existing", "既存板")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("authentication")
	}
	_, page := c.request("GET", "/boards/new", "", nil)
	csrf := pageFields(page).Get("csrf")
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 3; i++ {
			fields := url.Values{"bbs": {"existing"}, "subject": {fmt.Sprintf("投稿%d", i)}, "MESSAGE": {fmt.Sprintf("投稿%d", i)}, "oimo_request_id": {fmt.Sprintf("concurrent-board-post-%02d", i)}}
			accepted, e := sendFormOnce(form, fields, "")
			// 板追加による公開版変更で確認が更新された場合も、返された最新tokenで続ける。
			for retry := 0; e == nil && accepted.Confirmation != nil && retry < 10; retry++ {
				accepted, e = sendFormOnce(form, fields, accepted.Confirmation.Token)
			}
			if e != nil {
				done <- e
				return
			}
			if !accepted.Accepted {
				done <- fmt.Errorf("posting rejected: %+v", accepted)
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 3; i++ {
		fields := url.Values{"csrf": {csrf}, "key": {fmt.Sprintf("added%d", i)}, "name": {"追加板"}}
		res, body := c.request("POST", "/boards", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 303 {
			t.Errorf("create during posting: %d %s", res.StatusCode, body)
		}
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	_, boards, e := repo.webBoards()
	if e != nil || len(boards) != 4 {
		t.Fatal(boards, e)
	}
}
