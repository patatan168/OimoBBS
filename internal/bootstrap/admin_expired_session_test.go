// セッション失効後も認証前のログイン資産で表示を整え、元ページの資産は拒否する。
package bootstrap

import (
	"net/http"
	"oimobbs/internal/webui"
	"regexp"
	"strings"
	"testing"
)

func TestAdminExpiredSessionLoginAssets(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := c.request("GET", "/operations", "", nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	privateAsset, _ := webui.AdminAssetPath("admin-settings.css", "", "/operations")
	repo.adminAuth.Delete(c.cookies["oimo_admin"].Value)
	res, body = c.request("GET", "/operations", "", nil)
	if res.StatusCode != 401 || !strings.Contains(body, "ログインの有効期限") || !strings.Contains(body, `data-login-form`) || strings.Contains(body, "data-settings-review") {
		t.Fatal("expired HTML", res.StatusCode)
	}
	assets := regexp.MustCompile(`(?:href|src)="(/web/assets/page/[^\"]+)"`).FindAllStringSubmatch(body, -1)
	if len(assets) != 6 {
		t.Fatal("login assets", len(assets))
	}
	for _, asset := range assets {
		res, _ = c.request("GET", asset[1], "", nil)
		if res.StatusCode != 200 {
			t.Fatal("expired login asset denied", asset[1], res.StatusCode)
		}
	}
	for _, method := range []string{"GET", "HEAD"} {
		res, _ = c.request(method, privateAsset, "", http.Header{"If-None-Match": {"*"}})
		if res.StatusCode != 401 {
			t.Fatal("private asset escaped auth", res.StatusCode)
		}
	}
	res, body = c.request("GET", "/api/v1/operations", "", nil)
	if res.StatusCode != 401 || !strings.Contains(res.Header.Get("Content-Type"), "application/json") || !strings.Contains(body, "AUTHENTICATION_REQUIRED") {
		t.Fatal("API boundary", res.StatusCode)
	}
}
