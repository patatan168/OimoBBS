// 保存ログからNGワード登録・解除までを隔離した実ブラウザで確認する。
package bootstrap

import (
	"net/http/httptest"
	"oimobbs/internal/domain"
	"oimobbs/internal/securitylog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecurityEventsBrowser(t *testing.T) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMでブラウザ検証を有効化")
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "listui", "一覧の表示確認")
	if err != nil {
		t.Fatal(err)
	}
	b := repo.posting[board.ID]
	now := domain.Time(time.Now().UnixNano())
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		for i := range 3 {
			starts := now - 3600e9
			expires := now + 3600e9
			revision := domain.U64(1)
			enabled := true
			if i == 1 {
				expires = now - 1e9
			}
			if i == 2 {
				enabled = false
				revision = 2
			}
			rule := denialRule{ID: domain.NewID(), Revision: revision, Scope: denialScope{"board", board.ID}, Operations: []string{"create", "reply"}, Conditions: []denialCondition{{"body", "contains", strings.Repeat("長い規制条件の表示確認。", 5), "deny"}}, Effect: denialEffect{Type: "deny"}, Starts: starts, Expires: expires, Reason: "spam", Enabled: enabled}
			c, e := compileDenial(rule)
			if e != nil {
				return nil, e
			}
			b.denials[rule.ID] = c
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []securitylog.Event{
		{At: time.Now(), Source: "similar", Reason: "過去の確認用ログ", Body: "表示しない過去の確認用ログ", Dummy: true},
		{At: time.Now(), Source: "similar", Reason: "類似本文の連投", Body: "確認用の宣伝文。<script>window.bad=true</script>", MatchBody: "確認用の宣伝文。"},
		{At: time.Now(), Source: "waf", Reason: "path", Path: "/.git/config/" + strings.Repeat("long-path", 30), Rejected: true},
		{At: time.Now(), Source: "similar", Reason: "類似本文の連投", Body: "別の本文を拒否した例です。" + strings.Repeat("長い本文の表示確認。", 100), Rejected: true},
	} {
		repo.securityLog.Add(event)
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "http://localhost:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	repo.cfg.Admin.Transport, repo.cfg.Admin.Origin, repo.cfg.Public.BaseURL = "public_path", origin+"/admin", origin
	// 攻撃文がqueryに載らず、WAFがONでもログから規制画面へ移動できることを確認する。
	policy := repo.wafSettings()
	policy.Enabled = true
	policy.Traffic.Enabled = false
	repo.publishWAF(policy)
	admin, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = admin.Handler
	server.Start()
	script, err := filepath.Abs("../../scripts/test-security-events-browser.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, script)
	command.Env = append(os.Environ(), "OIMO_SECURITY_URL="+origin+"/admin", "OIMO_TEST_PASSWORD="+adminTestSecret, "OIMO_RULE_LIST_PATH=/boards/"+board.ID.String()+"/rules")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	}
	t.Log(string(output))
}
