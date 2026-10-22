// 廃止済み項目と利用できない権限の組み合わせを、HTML/APIの保存境界で拒否する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"oimobbs/internal/adminaccess"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

func TestAdminAccessCatalogHTTPValidation(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	board, err := repo.CreateBoard(t.Context(), "catalog", "権限整理")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, role  string
		permissions []string
		message     string
	}{
		{"removed.role", "reporter", []string{}, "有効なロール"},
		{"removed.viewer", "viewer", []string{}, "有効なロール"},
		{"removed.permission", "site_admin", []string{"private_posts.read"}, "廃止済み"},
		{"removed.read", "moderator", []string{"evidence.read"}, "廃止済み"},
		{"removed.hold", "moderator", []string{"evidence.hold"}, "廃止済み"},
		{"removed.export", "moderator", []string{"evidence.export"}, "廃止済み"},
		{"removed.transfer", "moderator", []string{"evidence.transfer"}, "廃止済み"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, _ := c.request("GET", "/api/v1/administrators", "", nil)
			boards := []domain.ID{board.ID}
			if tc.role == "site_admin" {
				boards = []domain.ID{}
			}
			input := accountInput{Login: tc.name, Display: "入力を保持", Password: adminTestSecret, Access: AdministratorAccess{Role: tc.role, Boards: boards, Permissions: tc.permissions, Enabled: true}}
			before := repo.site.State().Seq
			res, _, body := c.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
			if res.StatusCode != 422 || !strings.Contains(body, "INVALID_ACCESS") || repo.site.State().Seq != before {
				t.Fatal("API accepted invalid access", res.StatusCode, body)
			}
			_, page := c.request("GET", "/administrators", "", nil)
			fields := pageFields(page)
			// 無効な選択肢自体は廃止済みとして拒否する。現在の選択肢の組み合わせは説明付きで再表示する。
			fields.Set("role", tc.role)
			fields.Set("login_name", tc.name)
			fields.Set("display_name", input.Display)
			fields.Set("password", adminTestSecret)
			fields.Set("enabled", "true")
			if len(boards) > 0 {
				fields.Set("board_ids", board.ID.String())
			}
			fields["extra_permissions"] = tc.permissions
			res, body = c.request("POST", "/administrators", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
			expected := 422
			if len(tc.permissions) > 0 {
				expected = 400
			}
			if res.StatusCode != expected || repo.site.State().Seq != before || strings.Contains(body, adminTestSecret) {
				t.Fatal("HTML accepted invalid access", res.StatusCode)
			}
			if expected == 422 && !strings.Contains(body, tc.message) {
				t.Fatal("missing validation explanation", tc.message)
			}
		})
	}
	// 有効な最小ロールと2つの追加権限が、同じ定義から表示される。
	_, page := c.request("GET", "/administrators", "", nil)
	for _, text := range []string{"3つのロール", "通常の管理操作", "非公開情報の取り扱い", "投稿原本", "提出用ファイル", "利用条件"} {
		if !strings.Contains(page, text) {
			t.Errorf("missing guide: %s", text)
		}
	}
	for _, removed := range []string{`value="reporter"`, `value="private_posts.read"`, "予約項目"} {
		if strings.Contains(page, removed) {
			t.Errorf("removed item remains: %s", removed)
		}
	}
	// 原本閲覧と保全の組を保存し、APIと再読込画面の選択を確認する。
	list, _ := c.request("GET", "/api/v1/administrators", "", nil)
	input := accountInput{Login: "catalog.viewer", Display: "閲覧と保全", Password: adminTestSecret, Access: AdministratorAccess{Role: "moderator", Boards: []domain.ID{board.ID}, Permissions: []string{"evidence.manage"}, Enabled: true}}
	res, account, body := c.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 || len(account.Access.Permissions) != 1 {
		t.Fatal(res.StatusCode, body)
	}
	_, page = c.request("GET", "/administrators/"+account.ID.String(), "", nil)
	for _, value := range []string{"evidence.manage"} {
		if !strings.Contains(page, `value="`+value+`" checked`) {
			t.Fatal("saved permission lost", value)
		}
	}
	detail, body := c.request("GET", "/api/v1/administrators/"+account.ID.String(), "", nil)
	var saved struct {
		Data AdminAccount `json:"data"`
	}
	if detail.StatusCode != 200 || json.Unmarshal([]byte(body), &saved) != nil || saved.Data.Access.Role != "moderator" {
		t.Fatal("saved access unavailable")
	}
}

// TestAdminInheritedAccess は保存値に依存しない上位ロールの実効権限と、HTMLの変更不可表示を確認する。
func TestAdminInheritedAccess(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	board, e := r.CreateBoard(t.Context(), "inherited", "担当板")
	if e != nil {
		t.Fatal(e)
	}
	other, e := r.CreateBoard(t.Context(), "inheritedother", "担当外")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		role  string
		grant bool
	}{{"moderator", false}, {"moderator", true}, {"board_admin", false}, {"site_admin", false}} {
		boards := []domain.ID{board.ID}
		if tc.role == "site_admin" {
			boards = []domain.ID{}
		}
		perms := []string{}
		if tc.grant {
			perms = []string{"evidence.manage"}
		}
		login := tc.role
		if tc.grant {
			login += ".granted"
		}
		a, e := r.CreateAdministrator(login, login, adminTestSecret, AdministratorAccess{Role: tc.role, Boards: boards, Permissions: perms, Enabled: true})
		if e != nil {
			t.Fatal(e)
		}
		r = reopenPrivilegeFixture(t, cfg, r)
		c := newAdminClient(t, r)
		if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
			t.Fatal("owner login")
		}
		_, page := c.request("GET", "/administrators/"+a.ID.String(), "", nil)
		for _, p := range adminaccess.Permissions() {
			marker := `value="` + p.Value + `" checked disabled`
			if strings.Contains(page, marker) != adminaccess.IncludesExtras(tc.role) {
				t.Fatal("inherited permission control", tc.role, p.Value)
			}
		}
		for _, id := range []domain.ID{board.ID, other.ID} {
			marker := `value="` + id.String() + `" checked disabled`
			if strings.Contains(page, marker) != (tc.role == "site_admin") {
				t.Fatal("site board control", tc.role, id)
			}
		}
		cookie, session, e := r.adminAuth.Create(a.ID, a.Generation, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		_ = cookie
		for _, id := range []domain.ID{board.ID, other.ID} {
			r.mu.Lock()
			err := r.authorizeEvidence(session, "evidence.manage", id, false)
			r.mu.Unlock()
			allowed := (tc.grant || adminaccess.IncludesExtras(tc.role)) && (tc.role == "site_admin" || id == board.ID)
			if (err == nil) != allowed {
				t.Fatal("records boundary", tc.role, tc.grant, id, err)
			}
		}
		c.server.Close()
	}
}
