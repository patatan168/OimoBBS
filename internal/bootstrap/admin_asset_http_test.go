// 表示元HTMLとCSS/JSの役割・担当板・再認証・失効・キャッシュの境界を実HTTPで比較する。
package bootstrap

import (
	"net/http"
	"oimobbs/internal/domain"
	"oimobbs/internal/webui"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAdminPageAssetsSameAuthorization(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "assetscope", "担当板")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "assetother", "担当外")
	if err != nil {
		t.Fatal(err)
	}
	type actor struct {
		login, role string
		info        AdministratorInfo
	}
	actors := []actor{{login: "asset.board", role: "board_admin"}, {login: "asset.mod", role: "moderator"}, {login: "asset.site", role: "site_admin"}}
	for i := range actors {
		boards := []domain.ID{board.ID}
		if actors[i].role == "site_admin" {
			boards = nil
		}
		actors[i].info, err = repo.CreateAdministrator(actors[i].login, "資産担当", adminTestSecret, AdministratorAccess{Role: actors[i].role, Boards: boards, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		repo = reopenPrivilegeFixture(t, cfg, repo)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	for _, a := range actors {
		raw, session, err := repo.adminAuth.Create(a.info.ID, a.info.Generation, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		c.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: raw}
		for _, tc := range []struct{ page, name string }{
			{"/boards", "list.js"}, {"/auto-reports", "admin-reports.css"}, {"/reports", "ui.css"}, {"/evidence", "ui.css"}, {"/maintenance", "ui.css"},
			{"/waf", "admin-waf.js"}, {"/waf-events", "admin-security.css"}, {"/global-rules", "admin-security.css"}, {"/waf?wrong=1", "admin-waf.js"}, {"/administrators", "admin-access.js"}, {"/audit", "admin-audit.css"}, {"/audit", "admin-audit.js"},
			{"/audit?board=" + other.ID.String(), "admin-audit.css"}, {"/audit?board=" + other.ID.String(), "admin-audit.js"},
			{"/boards/" + board.ID.String() + "/settings", "admin-board.js"},
			{"/boards/" + other.ID.String() + "/settings", "admin-board.js"},
			{"/boards/" + domain.NewID().String() + "/settings", "admin-board.js"},
			{"/boards/" + board.ID.String() + "/rules", "admin-rules.js"},
			{"/boards/" + board.ID.String() + "/reading", "admin-reading.css"},
			{"/manual", "admin-access.css"},
		} {
			html, htmlBody := c.request("GET", tc.page, "", nil)
			if html.StatusCode >= 400 {
				// 拒否画面の見た目まで元ページの権限に束縛すると、CSS/JSも拒否されて崩れる。
				assets := regexp.MustCompile(`(?:href|src)="(/web/assets/page/[^\"]+)"`).FindAllStringSubmatch(htmlBody, -1)
				if len(assets) == 0 {
					t.Fatal("error page has no recovery assets", tc.page)
				}
				for _, asset := range assets {
					res, _ := c.request("GET", asset[1], "", nil)
					if res.StatusCode != 200 {
						t.Fatal("error page asset denied", a.role, tc.page, res.StatusCode)
					}
				}
			}
			asset, err := webui.AdminAssetPath(tc.name, "", tc.page)
			if err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{"GET", "HEAD"} {
				res, body := c.request(method, asset, "", nil)
				if res.StatusCode != html.StatusCode || res.Header.Get("Location") != html.Header.Get("Location") || res.Header.Get("Cache-Control") != "no-store" {
					t.Fatalf("role=%s page=%s method=%s HTML=%d %s asset=%d %s", a.role, tc.page, method, html.StatusCode, html.Header.Get("Location"), res.StatusCode, res.Header.Get("Location"))
				}
				if method == "HEAD" && body != "" {
					t.Fatal("HEAD body")
				}
				if res.StatusCode == 200 && method == "GET" && !strings.Contains(res.Header.Get("Content-Type"), "text/") {
					t.Fatal("asset content type")
				}
				// 条件付き取得でも認可結果を304で上書きしない。
				if html.StatusCode != 200 {
					res, _ = c.request(method, asset, "", http.Header{"If-None-Match": {"*"}})
					if res.StatusCode != html.StatusCode {
						t.Fatal("conditional authorization", a.role, tc.page, res.StatusCode)
					}
				}
			}
		}
		if a.role == "site_admin" {
			// 管理者画面に必要な再認証もHTMLと同じ。再認証後にだけ資産を返す。
			raw, _, err = repo.adminAuth.MarkReauthenticated(raw, session, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			c.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: raw}
			html, _ := c.request("GET", "/administrators", "", nil)
			asset, _ := webui.AdminAssetPath("admin-access.js", "", "/administrators")
			res, _ := c.request("GET", asset, "", nil)
			if html.StatusCode != 200 || res.StatusCode != 200 {
				t.Fatal("reauthenticated assets", html.StatusCode, res.StatusCode)
			}
			// ページ名を権限の低い画面へ差し替えても、その画面にない資産は配らない。
			for _, page := range []string{"/login", "/manual", "/api/v1/waf", "/robots.txt", "/web/assets/ui.css", "/../waf"} {
				path, _ := webui.AdminAssetPath("admin-waf.js", "", page)
				res, _ := c.request("GET", path, "", http.Header{"Referer": {cfg.Admin.Origin + "/waf"}})
				if res.StatusCode != 404 {
					t.Fatal("forged source page", page, res.StatusCode)
				}
			}
			// 同じURLでもログアウトで失効する。ローカル保存による認可迂回も禁止。
			repo.adminAuth.Delete(raw)
			res, _ = c.request("GET", asset, "", http.Header{"If-None-Match": {"*"}})
			if res.StatusCode != 401 {
				t.Fatal("revoked assets", res.StatusCode)
			}
		}
	}
}

// TestAdminPageAssetsPreserveAuditSnapshots は資産取得で監査のページ送り枠を使い切らないことを確認する。
func TestAdminPageAssetsPreserveAuditSnapshots(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	for _, key := range []string{"assetone", "assettwo"} {
		if _, err := repo.CreateBoard(t.Context(), key, key); err != nil {
			t.Fatal(err)
		}
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := c.request("GET", "/audit?limit=1", "", nil)
	before := len(repo.auditSnapshots)
	if res.StatusCode != 200 || before != 1 {
		t.Fatal("paged audit fixture", res.StatusCode, before)
	}
	matches := regexp.MustCompile(`(?:href|src)="(/web/assets/page/[^"]+)"`).FindAllStringSubmatch(body, -1)
	if len(matches) != 8 {
		t.Fatal("audit assets", len(matches))
	}
	for range 3 {
		for _, asset := range matches {
			res, _ = c.request("GET", asset[1], "", nil)
			if res.StatusCode != 200 {
				t.Fatal("asset exhausted audit pagination", res.StatusCode)
			}
		}
	}
	if len(repo.auditSnapshots) != before {
		t.Fatal("asset allocated audit snapshots")
	}
}

// TestAdminListAssetsDoNotQueueBoardReads は権限確認後の資産取得が板の一覧集計を実行しないことを確認する。
func TestAdminListAssetsDoNotQueueBoardReads(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "assetbusy", "集計待ちの板")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.server.Client().Timeout = 2 * time.Second
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = repo.posting[board.ID].worker.Submit(t.Context(), func() (any, error) { close(started); <-release; return nil, nil })
	}()
	<-started
	defer func() { close(release); <-done }()
	for _, tc := range []struct{ page, name string }{{"/boards", "list.js"}, {"/auto-reports", "admin-reports.css"}, {"/audit?board=" + board.ID.String(), "admin-audit.css"}, {"/boards/" + board.ID.String() + "/rules", "admin-rules.js"}} {
		path, err := webui.AdminAssetPath(tc.name, "", tc.page)
		if err != nil {
			t.Fatal(err)
		}
		res, body := c.request("GET", path, "", nil)
		if res.StatusCode != 200 || body == "" {
			t.Fatal("asset waited for board row enumeration", tc.page, res.StatusCode)
		}
	}
}
