// 公開・管理の各接続方式で、経路変形や転送ヘッダーによってWAF全体を外せないことを確認する。
package bootstrap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"oimobbs/internal/waf"
)

func TestWAFTransportRouteCoverage(t *testing.T) {
	for _, mode := range []string{"loopback_tunnel", "public_path", "direct_https", "edge_public_path"} {
		for _, h2 := range []bool{false, true} {
			if h2 && (mode == "loopback_tunnel" || mode == "public_path") {
				continue
			}
			t.Run(mode+map[bool]string{false: "/http1", true: "/http2"}[h2], func(t *testing.T) {
				cfg, repo := adminFixture(t)
				defer repo.Close()
				var configured *http.Server
				var transport *http.Transport
				var err error
				base := ""
				if mode == "direct_https" || mode == "edge_public_path" {
					clientTLS, _ := proxyCertificates(t, &cfg)
					transport = &http.Transport{TLSClientConfig: clientTLS, ForceAttemptHTTP2: h2}
					defer transport.CloseIdleConnections()
				}
				switch mode {
				case "loopback_tunnel":
					repo.cfg = cfg
					configured, err = repo.AdminHTTPServer()
				case "direct_https":
					cfg.Edge, cfg.TrustedProxies = nil, []string{}
					cfg.Admin.Transport, cfg.Admin.Origin = "direct_https", "https://localhost:9081"
					repo.cfg = cfg
					configured, err = repo.AdminHTTPServer()
				default:
					base = "/admin"
					cfg.Admin.Transport, cfg.Admin.Listen, cfg.Admin.Origin = "public_path", "", cfg.Public.BaseURL+base
					repo.cfg = cfg
					configured, err = repo.ValidationHTTPServer()
				}
				if err != nil {
					t.Fatal(err)
				}
				policy := WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()}
				policy.Traffic.Enabled = false // 頻度拒否で検査経路の不備を覆わない。
				repo.publishWAF(policy)
				server := httptest.NewUnstartedServer(configured.Handler)
				server.Config = configured
				server.EnableHTTP2 = h2
				if transport != nil {
					// httptestはServeTLSを通さないため、実際のServeTLSと同じALPNを明示する。
					if h2 {
						configured.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
					}
					server.TLS = configured.TLSConfig.Clone()
					server.StartTLS()
				} else {
					server.Start()
				}
				defer server.Close()
				client := server.Client()
				if transport != nil {
					client = &http.Client{Transport: transport}
				}
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				origin := cfg.Admin.Origin
				if base != "" {
					origin = cfg.Public.BaseURL
				}
				u, _ := url.Parse(origin)
				for i, path := range []string{base + "/login", base, base + "/api/v1/site", base + "/api/v1/waf", base + "/api/v1/otp/login", base + "/api/v1/passkey/login/begin", base + "/web/assets/ui.css", "/", "/test/bbs.cgi", "/web/post", "/search?q=normal", "/reports", "/%61dmin/login", "//admin/login", "/admin/../login", "/admin;ignored/login", "/missing"} {
					for _, method := range []string{"GET", "POST", "HEAD"} {
						req, _ := http.NewRequest(method, server.URL+path, nil)
						req.Host = u.Host
						if mode == "edge_public_path" {
							req.Header = edgeTestHeaders()
						}
						req.Header.Set("User-Agent", strings.Repeat("a", 1025))
						req.Header.Set("X-Original-URL", "/login")
						req.Header.Set("X-Rewrite-URL", "/login")
						req.Header.Set("X-HTTP-Method-Override", "GET")
						res, err := client.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						io.Copy(io.Discard, res.Body)
						res.Body.Close()
						if res.StatusCode != 403 || h2 && res.ProtoMajor != 2 || len(res.Cookies()) != 0 {
							t.Fatalf("WAF route escaped: %s %s status=%d proto=%s", method, path, res.StatusCode, res.Proto)
						}
					}
					if i == 0 {
						req, _ := http.NewRequest("GET", server.URL+base+"/login", nil)
						req.Host = u.Host
						if mode == "edge_public_path" {
							req.Header = edgeTestHeaders()
						}
						res, err := client.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						io.Copy(io.Discard, res.Body)
						res.Body.Close()
						if res.StatusCode != 200 || len(res.Cookies()) != 1 {
							t.Fatal("valid login page control", res.StatusCode)
						}
					}
				}
			})
		}
	}
}
