// 外部管理HTTPSの認証、Cookie、クローラーとOrigin拒否を検証する。
package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// publicAdminFixture は管理Originにも有効な隔離証明書を生成する。
func publicAdminFixture(t *testing.T) (*Repository, *x509.CertPool) {
	t.Helper()
	cfg, repo := adminFixture(t)
	t.Cleanup(func() { repo.Close() })
	cfg.Public.Listen = "127.0.0.1:9443"
	cfg.Public.BaseURL = "https://localhost:9443"
	cfg.Admin.Listen = "0.0.0.0:9444"
	cfg.Admin.Origin = "https://localhost:9444"
	cfg.Admin.Transport = "direct_https"
	cfg.Public.TLSCert = filepath.Join(filepath.Dir(cfg.DataDir), "cert.pem")
	cfg.Public.TLSKey = filepath.Join(filepath.Dir(cfg.DataDir), "key.pem")
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.Public.TLSCert, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.Public.TLSKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	repo.cfg = cfg
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(raw)
	return repo, roots
}

func TestPublicAdminHTTPS(t *testing.T) {
	repo, roots := publicAdminFixture(t)
	// URLのschemeは大小文字を同一視する。表記が違ってもHTTPS Cookieを弱めない。
	repo.cfg.Admin.Origin = "HTTPS://localhost:9444"
	server, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(server.Handler)
	s.TLS = server.TLSConfig.Clone()
	s.StartTLS()
	defer s.Close()
	s.Client().Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}
	defer s.Client().CloseIdleConnections()
	s.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client := &adminClient{t, s, map[string]*http.Cookie{}, repo.cfg.Admin.Origin}
	res, _ := client.request("GET", "/", "", nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/login" {
		t.Fatal("unauthenticated root", res.StatusCode)
	}
	res, _ = client.request("GET", "/api/v1/site", "", nil)
	if res.StatusCode != 401 {
		t.Fatal("unauthenticated API", res.StatusCode)
	}
	if client.login("incorrect-password-value") != 401 {
		t.Fatal("invalid password accepted")
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login failed")
	}
	for _, cookie := range client.cookies {
		if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatal("unsafe HTTPS cookie", cookie.Name)
		}
	}
	res, _ = client.site()
	if res.StatusCode != 200 {
		t.Fatal("authenticated API", res.StatusCode)
	}
	res, body := client.request("GET", "/robots.txt", "", nil)
	if res.StatusCode != 200 || body != "User-agent: *\nDisallow: /\n" {
		t.Fatal("robots", res.StatusCode, body)
	}
	for _, path := range []string{"/login", "/manual", "/api/v1/site", "/web/assets/ui.css"} {
		res, body = client.request("GET", path, "", http.Header{"User-Agent": {"Googlebot"}})
		if res.StatusCode != 403 || len(res.Cookies()) != 0 || strings.Contains(body, "csrf") {
			t.Fatal("crawler gate", path, res.StatusCode)
		}
		if !strings.Contains(res.Header.Get("X-Robots-Tag"), "noindex") {
			t.Fatal("noindex", path)
		}
	}
	res, _ = client.request("GET", "/manual", "", http.Header{"Sec-Fetch-Site": {"cross-site"}})
	if res.StatusCode != 403 {
		t.Fatal("cross-site GET", res.StatusCode)
	}
	res, _ = client.request("POST", "/logout", "", http.Header{"Origin": {"https://attacker.invalid"}})
	if res.StatusCode != 403 {
		t.Fatal("cross-origin POST", res.StatusCode)
	}
	// 実TCP peerが外部でもTLS・Hostが一致する直接接続だけを許す。
	for _, tc := range []struct {
		tls    bool
		host   string
		status int
	}{{true, "localhost:9444", 200}, {false, "localhost:9444", 403}, {true, "other.invalid:9444", 403}} {
		req := httptest.NewRequest("GET", "https://"+tc.host+"/login", nil)
		req.RemoteAddr = "198.51.100.8:12345"
		if !tc.tls {
			req.TLS = nil
		}
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatal("transport boundary", tc, rec.Code)
		}
	}
}

func TestPublicAdminConfigRejectsUnsafeTransport(t *testing.T) {
	if _, err := LoadConfig("../../config.admin-public.example.json"); err != nil {
		t.Fatal("public admin example", err)
	}
	repo, _ := publicAdminFixture(t)
	cfg := repo.cfg
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Admin.Origin = "http://localhost:9444" },
		func(c *Config) { c.Admin.Transport = "loopback_tunnel" },
		func(c *Config) { c.Public.TLSKey = "" },
		func(c *Config) { c.Admin.Origin = c.Public.BaseURL },
	} {
		invalid := cfg
		change(&invalid)
		if invalid.validate() == nil {
			t.Fatal("unsafe admin configuration accepted")
		}
	}
	cfg.Admin.Origin = "https://not-in-certificate.invalid:9444"
	if err := cfg.checkTLS(time.Now()); err == nil {
		t.Fatal("wrong admin certificate hostname accepted")
	}
}
