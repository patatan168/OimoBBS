// 管理Cookieの偽造・用途混同・経路変形で、未認証要求が管理操作へ到達しないことを確認する。
package bootstrap

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/waf"
)

func TestUnauthenticatedAdminRouteMatrix(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	_, loginPage := c.request("GET", "/login", "", nil)
	nonce := c.cookies["oimo_admin_login"].Value
	if pageFields(loginPage).Get("csrf") == "" {
		t.Fatal("login form control")
	}
	accounts, err := repo.administrators()
	if err != nil || len(accounts) != 1 {
		t.Fatal("fixture account", err)
	}
	owner := accounts[0]
	revoked, _, err := repo.adminAuth.Create(owner.ID, owner.Generation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repo.adminAuth.Delete(revoked)
	forged := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	identities := []string{"", "oimo_admin=" + forged, "oimo_admin=" + strings.Repeat("A", 43), "oimo_admin=" + nonce, "oimo_admin=" + revoked, "oimo_admin=" + forged + "; oimo_admin=" + revoked, "oimo_anon=" + forged + "; oimo_admin_login=" + nonce}
	id := domain.NewID().String()
	routes := []string{"/api/v1/site", "/site", "/boards", "/api/v1/boards", "/administrators", "/api/v1/administrators", "/api/v1/administrators/" + owner.ID.String() + "/password-reset", "/password", "/api/v1/password", "/reauth", "/api/v1/reauth", "/passkeys", "/api/v1/passkey/register/begin", "/api/v1/passkey/register/finish", "/api/v1/passkey/reauth/begin", "/api/v1/passkey/remove/finish", "/api/v1/otp/register/begin", "/api/v1/otp/register/finish", "/api/v1/otp/register/qr", "/api/v1/otp/remove", "/api/v1/otp/policy", "/api/v1/otp/reauth", "/evidence", "/api/v1/evidence/cases", "/api/v1/evidence/other-cases", "/api/v1/evidence/cases/" + id + "/exports", "/reports", "/api/v1/reports", "/auto-reports", "/auto-reports/" + id + "/" + id + "/inspect", "/waf", "/api/v1/waf", "/operations", "/api/v1/operations", "/global-rules", "/api/v1/global-rules", "/anonymous", "/api/v1/anonymous", "/abuse-guard", "/networks", "/admin-access", "/audit", "/caps", "/maintenance", "/%61pi/v1/site", "//api/v1/site", "/login/../api/v1/site", "/api/v1/site;login", "/api/v1/site%00", "/api/v1%2fsite"}
	requests := 0
	for _, enabled := range []bool{false, true} {
		policy := WAFSettings{Enabled: enabled, Traffic: waf.DefaultTrafficSettings()}
		policy.Traffic.Enabled = false
		repo.publishWAF(policy)
		before := repo.site.State().Seq
		for _, cookie := range identities {
			for _, route := range routes {
				for _, method := range []string{"GET", "POST", "PATCH", "HEAD"} {
					c.cookies = map[string]*http.Cookie{}
					headers := http.Header{"Cookie": {cookie}, "Content-Type": {"application/json"}, "X-CSRF-Token": {forged}, "If-Match": {`"site:1"`}, "Idempotency-Key": {"unauthenticated-matrix-test"}, "Authorization": {"Bearer " + forged}, "X-Admin-Role": {"site_admin"}, "X-Forwarded-For": {"127.0.0.1"}, "X-HTTP-Method-Override": {"GET"}}
					res, body := c.request(method, route, `{"role":"site_admin","enabled":false}`, headers)
					requests++
					if res.StatusCode < 400 || res.StatusCode >= 500 || strings.Contains(body, adminTestSecret) {
						t.Fatalf("unauthenticated route progressed: WAF=%t %s %s status=%d", enabled, method, route, res.StatusCode)
					}
					for _, issued := range res.Cookies() {
						if issued.Name == "oimo_admin" && issued.MaxAge >= 0 && issued.Value != "" {
							t.Fatal("unauthenticated session issued")
						}
					}
				}
			}
		}
		if repo.site.State().Seq != before || repo.wafSettings().Enabled != enabled {
			t.Fatal("unauthenticated request changed durable state or WAF")
		}
	}
	t.Log(fmt.Sprintf("rejected %d unauthenticated management requests", requests))
	// 正常な認証が成立する対照を置き、全要求拒否のfixtureではないことも確認する。
	if c.login(adminTestSecret) != 303 {
		t.Fatal("valid login control")
	}
	if res, _ := c.request("GET", "/api/v1/site", "", nil); res.StatusCode != 200 {
		t.Fatal("valid authenticated control", res.StatusCode)
	}
}
