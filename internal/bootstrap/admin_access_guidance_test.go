// 閲覧権限と再認証を区別し、権限設定・再入力・元画面への遷移を実HTTPで確認する。
package bootstrap

import (
	"net/http"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestEvidencePermissionGuidance(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, page := c.request("GET", "/evidence", "", nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/reauth?return_to=%2Fevidence" {
		t.Fatal("inherited grant needs reauth", res.StatusCode)
	}
	res, body := c.request("GET", "/api/v1/evidence/cases", "", nil)
	if res.StatusCode != 403 || !strings.Contains(body, "REAUTHENTICATION_REQUIRED") {
		t.Fatal("reauth bypass")
	}

	res, _ = c.request("GET", "/administrators", "", nil)
	if res.StatusCode != 303 {
		t.Fatal("reauth needed for permission editing")
	}
	res, page = c.request("GET", res.Header.Get("Location"), "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "再認証して管理者の権限設定へ進む") {
		t.Fatal("permission destination")
	}
	// POSTの期限切れでも再認証への主操作を表示し、変更を実行しない。
	res, page = c.request("POST", "/boards", "", nil)
	if res.StatusCode != 403 || !strings.Contains(page, "再認証して管理画面へ戻る") || !strings.Contains(page, "/reauth?return_to=%2Fboards") {
		t.Fatal("post reauth guidance", res.StatusCode)
	}
}

func TestEvidenceReauthRetryAndReturn(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	if _, e := repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := c.request("GET", "/evidence", "", nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/reauth?return_to=%2Fevidence" {
		t.Fatal("reauth redirect")
	}
	target := res.Header.Get("Location")
	res, page := c.request("GET", target, "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "再認証して提出用ログへ進む") || !strings.Contains(page, "再認証をやめてサイト設定へ戻る") {
		t.Fatal("destination guidance")
	}
	fields := pageFields(page)
	fields.Set("password", "incorrect private password")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, page = c.request("POST", target, fields.Encode(), headers)
	if res.StatusCode != 401 || !strings.Contains(page, "パスワードが一致しません") || !strings.Contains(page, "action=\""+target+"\"") || strings.Contains(page, "incorrect private password") {
		t.Fatal("retry form", res.StatusCode, page)
	}
	if res, _ = c.request("GET", "/api/v1/evidence/cases", "", nil); res.StatusCode != 403 {
		t.Fatal("failed reauth bypass")
	}
	fields = pageFields(page)
	fields.Set("password", adminTestSecret)
	res, _ = c.request("POST", target, fields.Encode(), headers)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/evidence" {
		t.Fatal("retry return")
	}
	if res, _ = c.request("GET", "/evidence", "", nil); res.StatusCode != 200 {
		t.Fatal("authorized evidence")
	}
	// 外部URLを戻り先として使わない。
	res, page = c.request("GET", "/reauth?return_to=https%3A%2F%2Fexample.com", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "action=\"/reauth?return_to=%2F\"") {
		t.Fatal("unsafe return destination")
	}
}

func TestEvidencePermissionGuidanceForLimitedAdministrator(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	if _, e := repo.CreateAdministrator("reader", "閲覧担当", adminTestSecret, AdministratorAccess{Role: "moderator", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	_, page := c.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", "reader")
	fields.Set("password", adminTestSecret)
	res, _ := c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("login")
	}
	res, page = c.request("GET", "/evidence", "", nil)
	if res.StatusCode != 403 || !strings.Contains(page, "サイト管理者に設定を依頼") || strings.Contains(page, "自分の権限設定へ進む") {
		t.Fatal("limited administrator guidance")
	}
}
