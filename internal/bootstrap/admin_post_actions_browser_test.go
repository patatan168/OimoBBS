// 隔離した実データの管理画面から、投稿者規制・解除・スレッド停止・レス削除を検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
)

// TestAdminPostActionsBrowser は管理者認証と再認証を経て、既存APIへGUIから操作を接続する。
func TestAdminPostActionsBrowser(t *testing.T) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMでブラウザー検証を有効化")
	}
	cfg, repo, board := anonymousAdminFixture(t, "required")
	defer func() { repo.Close() }()
	// 実際のSLIP付きDATを表示し、専ブラ用タグが管理画面へ漏れないことも確認する。
	setup := newAdminClient(t, repo)
	if setup.login(adminTestSecret) != 303 {
		t.Fatal("setup login")
	}
	if err := repo.EnableSlip(); err != nil {
		t.Fatal(err)
	}
	res, settings := setup.board(board.String())
	edit := settings.Settings
	edit.Identity = &AdminIdentitySettings{IDMode: "required", SlipMode: "vvvvv", AllowStrengthen: true, Networks: []identity.NetworkClass{{CIDR: "127.0.0.0/8", Kind: "fixed", Label: "OCN", Suffix: "0", Provider: "ocn"}}}
	raw, err := json.Marshal(edit)
	if err != nil {
		t.Fatal(err)
	}
	response, _ := setup.request("PATCH", "/api/v1/boards/"+board.String()+"/settings", string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"post-browser-slip-settings"}})
	setup.server.Close()
	if response.StatusCode != 200 {
		t.Fatal("SLIP fixture settings", response.StatusCode)
	}
	posting, request, _ := anonymousHTTP(t, repo, siteID(repo.site.State()))
	fields := url.Values{"bbs": {"news"}, "subject": {"管理操作の対象"}, "MESSAGE": {"MANAGEMENT-TARGET-BODY"}, "oimo_request_id": {"admin-actions-browser-create"}}
	for range 3 {
		request("POST", "/test/bbs.cgi", fields)
	}
	posting.Close()
	var thread uint64
	for key := range repo.posting[board].threads {
		thread = key
	}
	if thread == 0 {
		t.Fatal("fixture post missing")
	}
	if _, err := repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	repo = reopenPrivilegeFixture(t, cfg, repo)
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "http://localhost:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	repo.cfg.Admin.Transport, repo.cfg.Admin.Origin, repo.cfg.Public.BaseURL = "public_path", origin+"/admin", origin
	admin, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "admin-actions-browser")
	if err != nil {
		t.Fatal(err)
	}
	public := repo.SiteWebHandler(observer)
	server.Config.ConnContext = observer.ConnContext
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") {
			admin.Handler.ServeHTTP(w, r)
			return
		}
		public.ServeHTTP(w, r)
	})
	server.Start()
	script, err := filepath.Abs("../../scripts/test-admin-post-actions-browser.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, script)
	command.Env = append(os.Environ(), "OIMO_ACTIONS_URL="+origin+"/admin", "OIMO_TEST_PASSWORD="+adminTestSecret, "OIMO_ACTIONS_BOARD="+board.String(), "OIMO_ACTIONS_THREAD="+fmt.Sprint(thread))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	}
	t.Log(string(output))
}
