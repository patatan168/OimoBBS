// Bot対策の実管理画面で、現在の停止と検出のみの条件成立を混同しないことを確認する。
package bootstrap

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBotGuardStatusBrowser は実フォームの保存・エラー・モード別表示を隔離ブラウザで検証する。
func TestBotGuardStatusBrowser(t *testing.T) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMでブラウザ検証を有効化")
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	now := trafficNow()
	for i := 1; i <= botFailureLimit; i++ {
		repo.bot.record(botHash(1), botHash(i), now)
	}
	repo.bot.record(botHash(2), botHash(1), now)
	_ = repo.bot.check(botHash(1), now)
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
	script, err := filepath.Abs("../../scripts/test-bot-status-browser.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, script)
	command.Env = append(os.Environ(), "OIMO_BOT_URL="+origin+"/admin", "OIMO_TEST_PASSWORD="+adminTestSecret)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	}
	t.Log(string(output))
}
