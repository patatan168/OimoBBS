// 自動通報原本の再認証案内とフォーム復帰を、実ブラウザーの表示・操作で検査する。
package bootstrap

import (
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestAdminAutoReportSecurityBrowser(t *testing.T) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMでブラウザー検証を有効化")
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	b, err := repo.CreateBoard(t.Context(), "review", "通報確認")
	if err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	err = repo.enableDenials(b.ID, true, false, false, false)
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	id := domain.NewID()
	policy := defaultReportPolicy()
	at := domain.Time(time.Now().UnixNano())
	rule := denialRule{ID: id, Revision: 1, Scope: denialScope{"board", b.ID}, Operations: []string{"create", "reply"}, Conditions: []denialCondition{{"token", "exact", domain.Hash{1}.String(), "deny"}}, Effect: denialEffect{Type: "deny"}, Starts: at, Expires: at + domain.Time(policy.stop()), Reason: "abuse", Enabled: true, ReportPolicy: &policy}
	for range 3 {
		rule.Reports = append(rule.Reports, autoReportEvidenceRef{domain.NewID(), autoReportReference{"review", 1, 1}})
	}
	rule.Reports[2].Operation = id
	board := repo.posting[b.ID]
	_, err = board.worker.Submit(t.Context(), func() (any, error) {
		compiled, err := compileDenial(rule)
		if err != nil {
			return nil, err
		}
		if err := appendControl(board.control, "auto_report_stop", []store.Mutation{mutation("board_rule", id.String(), rule, nil)}, []string{id.String()}); err != nil {
			return nil, err
		}
		board.denials[id] = compiled
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "http://" + server.Listener.Addr().String()
	repo.cfg.Admin.Origin = origin
	configured, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = configured.Handler
	server.Start()
	script, err := filepath.Abs("../../scripts/test-auto-report-security-browser.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, script)
	command.Env = append(os.Environ(), "OIMO_REPORT_REVIEW_URL="+origin+fmt.Sprintf("/auto-reports/%s/%s", b.ID, id), "OIMO_TEST_PASSWORD="+adminTestSecret)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
