// 再認証から10分経過した生存セッションで、画面・拒否・再認証後の復帰を確認する。
package bootstrap

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/adminauth"
)

// expiredReauthCookie は時計や本番処理を差し替えず、11分前に本人確認したテスト用セッションを作る。
func expiredReauthCookie(t *testing.T, repo *Repository, session adminauth.Session) string {
	t.Helper()
	past := time.Now().Add(-11 * time.Minute)
	raw, old, err := repo.adminAuth.Create(session.Admin, session.Generation, past)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err = repo.adminAuth.MarkReauthenticated(raw, old, past)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAdminReauthenticationExpiry(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	session, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw := expiredReauthCookie(t, repo, session)
	c.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: raw}
	expired, err := repo.adminAuth.Lookup(raw, time.Now())
	if err != nil || expired.Reauthenticated(time.Now()) {
		t.Fatal("fixture must be alive but reauthentication expired", err)
	}
	res, body := c.request("GET", "/passkeys", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "再認証して登録・削除へ進む") || strings.Contains(body, "data-passkey-register") || strings.Contains(body, "data-auth-policy-form") {
		t.Fatal("expired screen exposes changes", res.StatusCode)
	}
	res, _ = c.request("GET", "/administrators", "", nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/reauth?return_to=%2Fadministrators" {
		t.Fatal("expired GET return", res.StatusCode)
	}
	res, body = c.request("POST", "/boards", "", nil)
	if res.StatusCode != 403 || !strings.Contains(body, "再認証して管理画面へ戻る") || !strings.Contains(body, "自動で再実行しません") {
		t.Fatal("expired POST guidance", res.StatusCode)
	}
	assets := regexp.MustCompile(`(?:href|src)="(/web/assets/page/[^"]+)"`).FindAllStringSubmatch(body, -1)
	if len(assets) == 0 {
		t.Fatal("missing recovery styles")
	}
	for _, asset := range assets {
		response, _ := c.request("GET", asset[1], "", nil)
		if response.StatusCode != 200 {
			t.Fatal("expired error page asset", response.StatusCode)
		}
	}
	res, body = c.request("POST", passkeyRoute+"register/begin", `{}`, http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {expired.CSRF(passkeyRoute)}})
	if res.StatusCode != 403 || !strings.Contains(body, "REAUTHENTICATION_REQUIRED") {
		t.Fatal("expired passkey registration accepted", res.StatusCode)
	}
	res, body = c.request("GET", "/api/v1/reauth", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `"reauthenticated":false`) {
		t.Fatal("reauthentication status")
	}
	res, body = c.request("GET", "/reauth?return_to=%2Fboards", "", nil)
	fields := pageFields(body)
	fields.Set("password", adminTestSecret)
	res, _ = c.request("POST", "/reauth?return_to=%2Fboards", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 || res.Header.Get("Location") != "/boards" {
		t.Fatal("return after reauthentication", res.StatusCode)
	}
	res, _ = c.request("GET", "/administrators", "", nil)
	if res.StatusCode != 200 {
		t.Fatal("reauthentication failed to restore access", res.StatusCode)
	}
	if _, err = repo.adminAuth.Lookup(raw, time.Now()); err == nil {
		t.Fatal("old session survived reauthentication")
	}
}
