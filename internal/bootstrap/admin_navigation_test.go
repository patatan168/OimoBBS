// ロール・追加権限ごとの管理メニューを実HTTPで検査し、共有テンプレートの権限混線も検出する。
package bootstrap

import (
	"fmt"
	"net/http"
	"oimobbs/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestAdminNavigationPermissions(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "navigation", "メニュー検査")
	if err != nil {
		t.Fatal(err)
	}
	type navigationCase struct {
		role        string
		permissions []string
		account     AdministratorInfo
	}
	cases := []navigationCase{
		{role: "site_admin"},
		{role: "moderator"},
		{role: "moderator", permissions: []string{"private_reports.read"}},
		{role: "moderator", permissions: []string{"evidence.manage"}},
		{role: "moderator", permissions: []string{"private_reports.read", "evidence.manage"}},
		{role: "board_admin"},
	}
	for i := range cases {
		boards := []domain.ID{board.ID}
		if cases[i].role == "site_admin" {
			boards = []domain.ID{}
		}
		cases[i].account, err = repo.CreateAdministrator(fmt.Sprintf("navigation.%d", i), "メニュー担当", adminTestSecret, AdministratorAccess{Role: cases[i].role, Boards: boards, Permissions: cases[i].permissions, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		repo = reopenPrivilegeFixture(t, cfg, repo)
	}
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	defer c.server.Close()
	for _, tc := range append(cases, cases[0]) {
		t.Run(fmt.Sprintf("%s/%v", tc.role, tc.permissions), func(t *testing.T) {
			cookie, _, err := repo.adminAuth.Create(tc.account.ID, tc.account.Generation, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			c.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: cookie}
			res, body := c.request("GET", "/auto-reports", "", nil)
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode, body)
			}
			res, ownKeys := c.request("GET", "/passkeys", "", nil)
			if res.StatusCode != 200 || !strings.Contains(ownKeys, "自分のパスキー") {
				t.Fatal("own passkey page unavailable", res.StatusCode)
			}
			// PCとスマホのメニューは同じ許可済み項目を2回描画する。
			expected := map[string]bool{
				"/":               tc.role == "site_admin",
				"/administrators": tc.role == "site_admin",
				"/updates":        tc.role == "site_admin",
				"/terms":          tc.role == "site_admin",
				"/boards":         tc.role != "moderator",
				"/audit":          tc.role != "moderator",
				"/caps":           tc.role != "moderator",
				"/auto-reports":   true, "/manual": true, "/passkeys": true,
				"/reports": tc.role != "moderator", "/evidence": tc.role != "moderator",
			}
			for _, permission := range tc.permissions {
				if permission == "private_reports.read" {
					expected["/reports"] = true
				}
				if permission == "evidence.manage" {
					expected["/evidence"] = true
				}
			}
			header := strings.Split(strings.Split(body, "<header class=\"site-header\">")[1], "</header>")[0]
			for path, allowed := range expected {
				count := strings.Count(header, `href="`+path+`"`)
				want := 0
				if allowed {
					want = 2
					if path == "/" {
						want = 3
					}
				}
				if path == "/boards" && tc.role == "board_admin" {
					want++
				}
				if path == "/auto-reports" && tc.role == "moderator" {
					want++
				}
				if count != want {
					t.Fatalf("menu %s: got %d want %d", path, count, want)
				}
			}
			// マニュアルにある権限外の管理ページへの案内もリンクにはしない。
			res, body = c.request("GET", "/manual", "", nil)
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode)
			}
			for _, path := range []string{"/administrators", "/boards", "/audit", "/reports", "/evidence"} {
				if !expected[path] && strings.Contains(body, `href="`+path+`"`) {
					t.Fatalf("manual forbidden link %s", path)
				}
			}
		})
	}
}
