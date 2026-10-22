// 認証境界を維持して静的資産を配信し、分離したHTMLから参照できることを確認する。
package bootstrap

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestWebAssetsAndAdminBoundary(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	for _, path := range []string{"/web/assets/ui.css", "/web/assets/ui.js", "/web/assets/admin.js"} {
		res, _ := client.request("GET", path, "", nil)
		if res.StatusCode != 404 {
			t.Fatal("unscoped admin asset", path, res.StatusCode)
		}
	}
	res, body := client.request("GET", "/login", "", nil)
	if res.StatusCode != 200 || !regexp.MustCompile(`href="/web/assets/page/[A-Za-z0-9_-]+/[a-f0-9]{64}/ui.css"`).MatchString(body) || !regexp.MustCompile(`src="/web/assets/page/[A-Za-z0-9_-]+/[a-f0-9]{64}/ui.js"`).MatchString(body) {
		t.Fatal("login assets")
	}
	for _, match := range regexp.MustCompile(`(?:href|src)="(/web/assets/page/[^"]+)"`).FindAllStringSubmatch(body, -1) {
		res, _ := client.request("GET", match[1], "", nil)
		if res.StatusCode != 200 || res.Header.Get("Cache-Control") != "no-store" || len(res.Cookies()) != 0 {
			t.Fatal("login assets must not replace login CSRF cookies", match[1], res.StatusCode, res.Cookies())
		}
	}
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatal("CSP", csp)
	}
	res, _ = client.request("GET", "/api/v1/site", "", nil)
	if res.StatusCode != 401 {
		t.Fatal("authentication bypass")
	}
	res, _ = client.request("GET", "/web/assets/templates/admin.html", "", nil)
	if res.StatusCode != 404 {
		t.Fatal("template exposed")
	}
	res, _ = client.request("POST", "/web/assets/ui.js", "", nil)
	if res.StatusCode != 405 {
		t.Fatal("asset method")
	}
	// assetsという既存の有効な板キーと静的資産の経路を衝突させない。
	if _, e := repo.CreateBoard(context.Background(), "assets", "Assets板"); e != nil {
		t.Fatal(e)
	}
	public, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+"/assets/", nil))
	if w.Code != 200 {
		t.Fatal("board path shadowed", w.Code)
	}
	for _, path := range []string{"/web/assets/ui.css", "/web/assets/ui.js"} {
		w := httptest.NewRecorder()
		public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+path, nil))
		if w.Code != http.StatusOK || w.Body.Len() == 0 {
			t.Fatal("public asset", path, w.Code)
		}
		w = httptest.NewRecorder()
		public.Handler.ServeHTTP(w, httptest.NewRequest("HEAD", cfg.Public.BaseURL+path, nil))
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("asset HEAD", w.Code)
		}
	}
	w = httptest.NewRecorder()
	public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+"/", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "/admin.js") || !regexp.MustCompile(`src="/web/assets/[a-f0-9]{64}/ui.js"`).Match(w.Body.Bytes()) {
		t.Fatal("public page assets", w.Code)
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("admin login")
	}
	res, body = client.request("GET", "/", "", nil)
	adminScript := regexp.MustCompile(`src="(/web/assets/page/[A-Za-z0-9_-]+/[a-f0-9]{64}/admin.js)"`).FindStringSubmatch(body)
	if res.StatusCode != 200 || len(adminScript) != 2 {
		t.Fatal("admin page lost its script", res.StatusCode)
	}
	res, body = client.request("GET", adminScript[1], "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "enhanceAdminMenu") || strings.Contains(body, "enhanceDisplayCommands") || strings.Contains(body, "enhanceEndings") {
		t.Fatal("admin asset unavailable")
	}
}

// TestAdminPrivateAssets はページ付きの別名・版付きURL・HEAD・条件付き取得で管理認証を確認する。
func TestAdminPrivateAssets(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	authenticated := newAdminClient(t, repo)
	defer authenticated.server.Close()
	anonymous := newAdminClient(t, repo)
	defer anonymous.server.Close()
	if authenticated.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := authenticated.request("GET", "/waf", "", nil)
	if res.StatusCode != 200 {
		t.Fatal("waf", res.StatusCode)
	}
	match := regexp.MustCompile(`src="(/web/assets/page/[A-Za-z0-9_-]+/[a-f0-9]{64}/admin-waf.js)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("private script missing")
	}
	public, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{match[1], "/web/assets/page/" + base64.RawURLEncoding.EncodeToString([]byte("/waf")) + "/admin-waf.js"} {
		res, body = authenticated.request("GET", path, "", http.Header{"Accept-Encoding": {"identity"}})
		if res.StatusCode != 200 || body == "" || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("authenticated asset", path, res.StatusCode, res.Header)
		}
		etag := res.Header.Get("ETag")
		for _, method := range []string{"GET", "HEAD"} {
			headers := http.Header{"If-None-Match": []string{etag}, "Accept-Encoding": {"identity"}}
			res, _ = anonymous.request(method, path, "", headers)
			if res.StatusCode != 401 {
				t.Fatal("anonymous asset", method, path, res.StatusCode)
			}
			res, _ = authenticated.request(method, path, "", headers)
			if res.StatusCode != 304 || res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("authenticated conditional asset", method, path, res.StatusCode, res.Header)
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(method, cfg.Public.BaseURL+path, nil)
			req.Header = headers
			public.Handler.ServeHTTP(w, req)
			if w.Code != 404 {
				t.Fatal("private public-path asset", method, path, w.Code)
			}
		}
	}
	// 登録された全管理専用資産は公開側に出さず、ログイン用以外は管理側でも認証する。
	for _, name := range []string{"admin.css", "admin.js", "admin-auth.css", "admin-auth.js", "countries.js", "countries.css", "protection.css", "admin-settings.css"} {
		path := "/web/assets/" + name
		w := httptest.NewRecorder()
		public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+path, nil))
		if w.Code != 404 {
			t.Fatal("public admin asset", path, w.Code)
		}
		res, _ = anonymous.request("GET", path, "", nil)
		expected := 404
		if res.StatusCode != expected {
			t.Fatal("admin asset boundary", path, res.StatusCode)
		}
	}
}

// TestAdminHTMLBoundary はログイン前の管理HTMLとテンプレート直接取得を拒否する。
func TestAdminHTMLBoundary(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	for _, path := range []string{"/audit", "/boards", "/administrators", "/reading", "/waf", "/abuse-guard", "/operations", "/networks", "/rules", "/passkeys", "/manual", "/reports", "/maintenance"} {
		res, body := c.request("GET", path, "", nil)
		if res.StatusCode != 401 || res.Header.Get("Cache-Control") != "no-store" || strings.Contains(body, `name="password"`) {
			t.Fatal("anonymous admin HTML", path, res.StatusCode)
		}
	}
	public, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/audit", "/waf", "/operations", "/templates/admin.html", "/web/templates/admin.html", "/web/assets/templates/admin.html", "/internal/webui/templates/admin.html"} {
		w := httptest.NewRecorder()
		public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+path, nil))
		if w.Code != 404 {
			t.Fatal("public admin HTML", path, w.Code)
		}
	}
}
