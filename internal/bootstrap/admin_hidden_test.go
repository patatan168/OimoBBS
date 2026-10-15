// 隠し管理パスのHTTPS・認証・権限拒否・URLとCookieの範囲を実HTTPで検査する。
package bootstrap

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestHiddenAdminHTTPS(t *testing.T) {
	repo, roots := publicAdminFixture(t)
	const base = "/admin"
	repo.cfg.Admin.Transport = "public_path"
	repo.cfg.Admin.Origin = repo.cfg.Public.BaseURL + base + "/"
	server, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(server.Handler)
	s.TLS = server.TLSConfig.Clone()
	s.StartTLS()
	defer s.Close()
	s.Client().Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"}}
	defer s.Client().CloseIdleConnections()
	s.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client := &adminClient{t, s, map[string]*http.Cookie{}, repo.cfg.Public.BaseURL}
	res, _ := client.request("GET", base+"/", "", nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != base+"/login" {
		t.Fatal("login redirect", res.StatusCode, res.Header)
	}
	res, page := client.request("GET", base+"/login", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, `action="`+base+`/login"`) || !strings.Contains(page, `content="`+base+`"`) {
		t.Fatal("mounted login", res.StatusCode, page)
	}
	for _, asset := range regexp.MustCompile(`(?:href|src)="(`+base+`/web/assets/[^"]+)"`).FindAllStringSubmatch(page, -1) {
		req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+asset[1], nil)
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Body.Len() == 0 || !strings.Contains(rec.Header().Get("X-Robots-Tag"), "noindex") {
			t.Fatal("mounted asset", asset[1], rec.Code)
		}
	}
	for _, cookie := range res.Cookies() {
		if cookie.Path != base+"/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatal("cookie scope", cookie)
		}
	}
	fields := pageFields(page)
	fields.Set("login", "owner")
	fields.Set("password", adminTestSecret)
	res, _ = client.request("POST", base+"/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 || res.Header.Get("Location") != base+"/" {
		t.Fatal("mounted login POST", res.StatusCode, res.Header)
	}
	for _, path := range []string{"/", "/manual", "/boards", "/board-categories", "/networks", "/administrators", "/anonymous", "/reports", "/audit", "/operations"} {
		res, page = client.request("GET", base+path, "", nil)
		if res.StatusCode == 303 {
			target := res.Header.Get("Location")
			if !strings.HasPrefix(target, base+"/") {
				t.Fatal("mounted reauth redirect", path, res.Header)
			}
			res, page = client.request("GET", target, "", nil)
			if res.StatusCode != 200 || !strings.Contains(page, `action="`+target+`"`) {
				t.Fatal("mounted reauth form", res.StatusCode, page)
			}
			fields := pageFields(page)
			fields.Set("password", adminTestSecret)
			res, _ = client.request("POST", target, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
			if res.StatusCode != 303 || res.Header.Get("Location") != base+path {
				t.Fatal("mounted reauth return", res.StatusCode, res.Header)
			}
			res, page = client.request("GET", base+path, "", nil)
		}
		expected := http.StatusOK

		if res.StatusCode != expected {
			t.Fatal("mounted page", path, res.StatusCode, page)
		}
		for _, attr := range regexp.MustCompile(`(?:href|action|src)="(/[^\"]*)"`).FindAllStringSubmatch(page, -1) {
			if !strings.HasPrefix(attr[1], base+"/") {
				t.Fatal("root URL escaped mount", path, attr[1])
			}
		}
	}
	res, _ = client.request("GET", base+"/api/v1/site", "", nil)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"hidden-admin-update-0001"}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}}
	res, body := client.request("PATCH", base+"/api/v1/site", `{"name":"隠しパス更新"}`, headers)
	if res.StatusCode != 200 || !strings.Contains(body, "隠しパス更新") {
		t.Fatal("mounted API save", res.StatusCode, body)
	}
	res, _ = client.request("POST", base+"/logout", "", http.Header{"Origin": {"https://attacker.invalid"}})
	if res.StatusCode != 403 {
		t.Fatal("origin bypass", res.StatusCode)
	}
	for _, path := range []string{"", "/login", "/manual", "/api/v1/site", "/web/assets/admin.js"} {
		res, body = client.request("GET", base+path, "", http.Header{"User-Agent": {"GPTBot"}})
		if res.StatusCode != 403 || len(res.Cookies()) != 0 || strings.Contains(body, "csrf") || !strings.Contains(res.Header.Get("X-Robots-Tag"), "noindex") {
			t.Fatal("mounted crawler gate", path, res.StatusCode)
		}
	}
	for _, path := range []string{"/", "/robots.txt"} {
		req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+path, nil)
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), base) || strings.Contains(rec.Header().Get("Set-Cookie"), "oimo_admin") {
			t.Fatal("private path leaked publicly", path)
		}
	}
	for _, path := range []string{"/login", "/api/v1/site"} {
		req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+path, nil)
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Fatal("unmounted admin alias", path, rec.Code)
		}
	}
	for _, target := range []string{"http://localhost:9443" + base, "https://wrong.invalid:9443" + base + "/login"} {
		req := httptest.NewRequest("GET", target, nil)
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, req)
		if rec.Code != 403 || len(rec.Result().Cookies()) != 0 {
			t.Fatal("hidden transport boundary", target, rec.Code)
		}
	}
	for _, path := range []string{base + "/%6cogin", base + "/../login", base + "//login"} {
		req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+path, nil)
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, req)
		if rec.Code != 403 || len(rec.Result().Cookies()) != 0 {
			t.Fatal("noncanonical mounted path", path, rec.Code)
		}
	}
}

func TestHiddenAdminConfigBoundaries(t *testing.T) {
	repo, _ := publicAdminFixture(t)
	cfg := repo.cfg
	cfg.Admin.Transport = "public_path"
	for _, path := range []string{"/admin", "/admin/", "/_manage-0123456789abcdef", "/_manage-0123456789abcdef/"} {
		cfg.Admin.Origin = cfg.Public.BaseURL + path
		if err := cfg.validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, origin := range []string{cfg.Public.BaseURL, cfg.Public.BaseURL + "/short", cfg.Public.BaseURL + "/abcdefghijklmnop", cfg.Public.BaseURL + "/_manage-0123456789abcdef/child", cfg.Public.BaseURL + "/_manage-%30abcdef0123456789", cfg.Public.BaseURL + "/_manage-0123456789abcdef?x=1", cfg.Public.BaseURL + "/_manage-0123456789abcdef#", "https://other.invalid/_manage-0123456789abcdef", "http://localhost:9443/_manage-0123456789abcdef"} {
		cfg.Admin.Origin = origin
		if cfg.validate() == nil {
			t.Fatal("unsafe hidden URL accepted", origin)
		}
	}
}
