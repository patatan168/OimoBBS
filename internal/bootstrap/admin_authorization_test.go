// 役割と担当板の行列、存在の秘匿、CLI登録・世代失効・最後の管理者保護を検査する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestAdministratorRoleMatrix(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	board, e := r.CreateBoard(context.Background(), "scope", "担当板")
	if e != nil {
		t.Fatal(e)
	}
	other, e := r.CreateBoard(context.Background(), "outside", "担当外")
	if e != nil {
		t.Fatal(e)
	}
	access := AdministratorAccess{Role: "moderator", Boards: []domain.ID{board.ID}, Permissions: []string{}, Enabled: true}
	created, e := r.CreateAdministrator("limited", "担当者", adminTestSecret, access)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := r.AdminHTTPServer(); e != nil {
		t.Fatal(e)
	}
	_, session, sessionErr := r.adminAuth.Create(created.ID, created.Generation, time.Now())
	if sessionErr != nil {
		t.Fatal(sessionErr)
	}
	r.mu.Lock()
	original, e := r.currentAdminSession(session)
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	for role, rank := range adminRoleRank {
		a := original
		a.Role = role
		if role == "site_admin" {
			a.Boards = []domain.ID{}
		}
		for required, min := range adminRoleRank {
			for _, owner := range []domain.ID{board.ID, other.ID, {}} {
				err := authorizeAdministrator(a, required, owner)
				allowed := rank >= min && (role == "site_admin" || owner == board.ID)
				if (err == nil) != allowed {
					t.Fatalf("role=%s required=%s owner=%s err=%v", role, required, owner, err)
				}
			}
		}
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	_, page := client.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", "limited")
	fields.Set("password", adminTestSecret)
	res, body := client.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 || res.Header.Get("Location") != "/auto-reports" {
		t.Fatal(res.StatusCode, body)
	}
	res, body = client.request("GET", "/api/v1/boards", "", nil)
	if res.StatusCode != 403 || strings.Contains(body, board.ID.String()) || strings.Contains(body, other.ID.String()) {
		t.Fatal(res.StatusCode, body)
	}
	for _, owner := range []domain.ID{other.ID, domain.NewID()} {
		res, body = client.request("GET", fmt.Sprintf("/api/v1/boards/%s/settings", owner), "", nil)
		if res.StatusCode != 403 || !strings.Contains(body, "PERMISSION_DENIED") {
			t.Fatal("existence leaked", res.StatusCode, body)
		}
	}
	path := fmt.Sprintf("/api/v1/boards/%s/settings", board.ID)
	res, _ = client.request("GET", path, "", nil)
	if res.StatusCode != 403 {
		t.Fatal(res.StatusCode)
	}
	res, _ = client.request("PATCH", path, "{}", http.Header{"Content-Type": {"application/json"}})
	if res.StatusCode != 403 {
		t.Fatal("viewer write allowed", res.StatusCode)
	}
	res, _ = client.request("GET", "/api/v1/audit", "", nil)
	if res.StatusCode != 403 {
		t.Fatal("scope free audit", res.StatusCode)
	}
	client.server.Close()
	updated, e := r.SetAdministratorAccess("limited", AdministratorAccess{Role: "moderator", Boards: []domain.ID{board.ID}, Enabled: true})
	if e != nil || updated.Generation != created.Generation+1 {
		t.Fatal(updated, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	_, e = r.currentAdminSession(session)
	r.mu.Unlock()
	if !errors.Is(e, adminauth.ErrSession) {
		t.Fatal("old generation valid", e)
	}
	if _, e = r.SetAdministratorAccess("owner", AdministratorAccess{Role: "moderator", Enabled: true}); e == nil {
		t.Fatal("last site admin revoked")
	}
}

func TestAdministratorScopeValidation(t *testing.T) {
	id := domain.NewID()
	invalid := []administrator{
		{Role: "viewer", Boards: []domain.ID{}, Permissions: []string{}},
		{Role: "reporter", Boards: []domain.ID{}, Permissions: []string{}},
		{Role: "unknown", Boards: []domain.ID{}, Permissions: []string{}},
		{Role: "moderator", Boards: nil, Permissions: []string{}},
		{Role: "moderator", Boards: []domain.ID{id, id}, Permissions: []string{}},
		{Role: "moderator", Boards: []domain.ID{{}}, Permissions: []string{}},
		{Role: "site_admin", Boards: []domain.ID{id}, Permissions: []string{}},
		{Role: "moderator", Boards: []domain.ID{id}, Permissions: []string{"evidence.manage", "evidence.manage"}},
		{Role: "moderator", Boards: []domain.ID{id}, Permissions: []string{"private_posts.read", "unknown"}},
		{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.read"}},
	}
	for _, a := range invalid {
		if e := validateAdministratorScope(a); e == nil {
			t.Fatal("invalid scope accepted", a)
		}
	}
	if e := validateAdministratorScope(administrator{Role: "moderator", Boards: []domain.ID{}, Permissions: []string{}}); e != nil {
		t.Fatal("empty scope must represent no assigned boards", e)
	}
}
