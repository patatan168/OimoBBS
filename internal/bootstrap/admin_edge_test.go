// 同じ公開待受の管理画面でも、認証edgeの利用者IPで接続制限を適用することを実TLSで検査する。
package bootstrap

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSharedAdminEdgeUsesAuthenticatedClientIP(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	// 既存の管理APIで127.0.0.1だけを許可し、後から同じ公開待受へ移す。
	admin := newAdminClient(t, repo)
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	view, headers := readingGet(t, admin, "/api/v1/admin-access")
	view.Policy.Enabled = true
	view.Policy.AllowedCIDRs = []string{"127.0.0.1/32"}
	allow := true
	view.Policy.AllowLoopbackIP = &allow
	if res, body := readingSave(t, admin, "/api/v1/admin-access", view.Policy, readingHeaders(headers)); res.StatusCode != 200 {
		t.Fatal("policy", res.StatusCode, body)
	}
	admin.server.Close()
	clientTLS, _ := proxyCertificates(t, &cfg)
	const base = "/admin"
	cfg.Admin.Transport, cfg.Admin.Listen, cfg.Admin.Origin = "public_path", "", cfg.Public.BaseURL+base
	repo.cfg = cfg
	server, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewUnstartedServer(server.Handler)
	s.TLS = server.TLSConfig.Clone()
	s.StartTLS()
	defer s.Close()
	transport := &http.Transport{TLSClientConfig: clientTLS}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, ip := range []string{"127.0.0.1", "192.0.2.19"} {
		for _, route := range []string{"/login", "/web/assets/ui.css", "/evidence/sample.zip", "/api/v1/admin-access"} {
			req, _ := http.NewRequest("GET", s.URL+base+route, nil)
			req.Host = "localhost:9080"
			req.Header = edgeTestHeaders()
			req.Header.Set("X-Oimo-Client-IP", ip)
			req.Header.Del("X-Forwarded-For")
			res, e := client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if ip == "127.0.0.1" && route == "/login" {
				if res.StatusCode != 200 || len(res.Cookies()) != 1 || !res.Cookies()[0].Secure || res.Cookies()[0].Path != base+"/" {
					t.Fatal("allowed client", res.StatusCode)
				}
				if !strings.Contains(res.Header.Get("Content-Security-Policy"), "connect-src 'self'") {
					t.Fatal("same-origin admin API blocked by CSP")
				}
			} else if ip != "127.0.0.1" && (res.StatusCode != 403 || len(res.Cookies()) != 0 || strings.Contains(string(body), "password")) {
				t.Fatal("edge peer used instead of client IP", ip, route, res.StatusCode)
			}
		}
	}
	for _, headers := range []http.Header{nil, {"X-Forwarded-For": {"127.0.0.1"}}} {
		req, _ := http.NewRequest("GET", s.URL+base+"/login", nil)
		req.Host = "localhost:9080"
		req.Header = headers
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 400 || len(res.Cookies()) != 0 {
			t.Fatal("unverified metadata accepted", res.StatusCode)
		}
	}
	withoutCert := clientTLS.Clone()
	withoutCert.Certificates = []tls.Certificate{}
	bad := &http.Transport{TLSClientConfig: withoutCert}
	defer bad.CloseIdleConnections()
	if res, e := (&http.Client{Transport: bad}).Get(s.URL + base + "/login"); e == nil {
		res.Body.Close()
		t.Fatal("mTLS bypass")
	}
}

func TestSharedAdminLoopbackHTTPWithoutSecondPort(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	const base = "/admin"
	repo.cfg.Admin.Transport, repo.cfg.Admin.Listen, repo.cfg.Admin.Origin = "public_path", "", repo.cfg.Public.BaseURL+base
	server, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"127.0.0.1", "192.0.2.19"} {
		req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+base+"/login", nil)
		req.RemoteAddr = ip + ":45678"
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, req)
		if ip == "127.0.0.1" {
			if w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Secure {
				t.Fatal("loopback HTTP", w.Code)
			}
		} else if w.Code != 403 {
			t.Fatal("public plaintext admin accepted", w.Code)
		}
	}
}
