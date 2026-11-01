// 大量の実監査fixtureをそのままChromiumへ渡し、未選択の初期表示とページ送りを検証する。
package bootstrap

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// runAuditPagingBrowser は明示したブラウザ環境だけを使い、隔離管理パスの実画面を操作する。
func runAuditPagingBrowser(t *testing.T, repo *Repository, total uint32) {
	t.Helper()
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Log("browser not requested; HTTP pagination validated separately")
		return
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "http://localhost:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	repo.cfg.Admin.Transport, repo.cfg.Admin.Origin, repo.cfg.Public.BaseURL = "public_path", origin+"/admin", origin
	admin, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = admin.Handler
	server.Start()
	script, err := filepath.Abs("../../scripts/test-admin-audit-paging-browser.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, script)
	command.Env = append(os.Environ(), "OIMO_AUDIT_URL="+origin+"/admin", "OIMO_TEST_PASSWORD="+adminTestSecret, "OIMO_AUDIT_TOTAL="+strconv.FormatUint(uint64(total), 10))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	}
	t.Log(string(output))
}
