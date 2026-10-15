// 認証境界を維持して静的資産を配信し、分離したHTMLから参照できることを確認する。
package bootstrap

import (
	"context"
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
	for path, kind := range map[string]string{"/web/assets/ui.css": "text/css", "/web/assets/ui.js": "text/javascript", "/web/assets/admin.js": "text/javascript"} {
		res, body := client.request("GET", path, "", nil)
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), kind) || body == "" {
			t.Fatal(path, res.StatusCode)
		}
	}
	res, body := client.request("GET", "/login", "", nil)
	if res.StatusCode != 200 || !regexp.MustCompile(`href="/web/assets/[a-f0-9]{64}/ui.css"`).MatchString(body) || !regexp.MustCompile(`src="/web/assets/[a-f0-9]{64}/ui.js"`).MatchString(body) {
		t.Fatal("login assets")
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
	adminScript := regexp.MustCompile(`src="(/web/assets/[a-f0-9]{64}/admin.js)"`).FindStringSubmatch(body)
	if res.StatusCode != 200 || len(adminScript) != 2 {
		t.Fatal("admin page lost its script", res.StatusCode)
	}
	res, body = client.request("GET", adminScript[1], "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "enhanceDisplayCommands") || !strings.Contains(body, "enhanceEndings") {
		t.Fatal("admin asset unavailable")
	}
}
