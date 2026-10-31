// 板別の設定で対象と現在地が共通表示され、同じ板の設定間を直接移動できることを検証する。
package bootstrap

import (
	"strings"
	"testing"
)

func TestAdminBoardNavigationAcrossSettings(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "navigation", "設定ナビの対象板")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	base := "/boards/" + board.ID.String()
	for _, section := range []string{"settings", "metadata", "reading", "thread-settings", "rules", "local-rules", "threads", "close"} {
		t.Run(section, func(t *testing.T) {
			res, body := c.request("GET", base+"/"+section, "", nil)
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode, body)
			}
			if !strings.Contains(body, `class="board-context"`) || !strings.Contains(body, `class="board-target-name">設定ナビの対象板`) || !strings.Contains(body, "設定中：") {
				t.Fatal("missing board context", body)
			}
			if !strings.Contains(body, `href="`+base+`/`+section+`" aria-current="page"`) {
				t.Fatal("missing current section", body)
			}
			for _, target := range []string{"settings", "metadata", "reading", "thread-settings", "rules", "local-rules", "threads", "close"} {
				if !strings.Contains(body, `href="`+base+`/`+target+`"`) {
					t.Fatal("missing direct setting", target)
				}
			}
		})
	}
	_, page := c.request("GET", "/reading", "", nil)
	if strings.Contains(page, `class="board-context"`) {
		t.Fatal("board navigation on global settings")
	}
}

func TestAdminBoardNavigationBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-board-navigation-browser.mjs")
}

// TestAdminBoardManagementBrowser は追加・改名後も共通ナビの対象板が更新されることを確認する。
func TestAdminBoardManagementBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-board-management-browser.mjs")
}
