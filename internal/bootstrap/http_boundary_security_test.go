// 公開・管理の共通URL境界と、管理画面への外部ブラウザ要求の拒否を検査する。
package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPPathSecurityBoundary(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	admin, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/./login", "/boards/../login", "//login", "/login\\extra", "/%6cogin", "/login%00", "/boards%2flogin"} {
		for _, side := range []string{"public", "admin"} {
			t.Run(side+route, func(t *testing.T) {
				origin, handler := repo.cfg.Admin.Origin, admin.Handler
				want := http.StatusForbidden
				if side == "public" {
					origin, handler = repo.cfg.Public.BaseURL, repo.SiteWebHandler(nil)
					want = http.StatusBadRequest
				}
				req := httptest.NewRequest("GET", origin+route, nil)
				req.RemoteAddr = "127.0.0.1:12345"
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if w.Code != want || len(w.Result().Cookies()) != 0 {
					t.Fatalf("malformed path progressed: status=%d", w.Code)
				}
			})
		}
	}
}

func TestAdminBrowserBoundaryBeforeLoginNonce(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	server, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range []string{"cross-site", "same-site", "invalid", ""} {
		req := httptest.NewRequest("GET", repo.cfg.Admin.Origin+"/login", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Sec-Fetch-Site", site)
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
			t.Fatalf("foreign browser issued login nonce: site=%s status=%d", site, w.Code)
		}
	}
	req := httptest.NewRequest("GET", repo.cfg.Admin.Origin+"/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header["Sec-Fetch-Site"] = []string{"same-origin", "same-origin"}
	w := httptest.NewRecorder()
	server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
		t.Fatal("duplicate browser metadata issued login nonce")
	}
	for _, site := range []string{"", "same-origin", "none"} {
		req := httptest.NewRequest("GET", repo.cfg.Admin.Origin+"/login", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK || len(w.Result().Cookies()) != 1 {
			t.Fatalf("local login rejected: site=%s status=%d", site, w.Code)
		}
	}
}
