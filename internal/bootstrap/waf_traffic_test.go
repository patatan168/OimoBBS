// 大量アクセス制限のHTTP応答、管理枠分離、edge本人確認と設定互換を検査する。
package bootstrap

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/waf"
	"strings"
	"testing"
)

func smallTrafficPolicy() WAFSettings {
	return WAFSettings{Enabled: true, Traffic: waf.TrafficSettings{Posting: waf.DefaultPostingSettings(), Enabled: true, ClientEnabled: true, ClientRate: 1, ClientBurst: 2, GlobalRate: 10, GlobalBurst: 20, ClientConcurrent: 2, GlobalConcurrent: 4, SearchRate: 1, SearchBurst: 2, SearchGlobalRate: 2, SearchGlobalBurst: 4, SearchConcurrent: 1}}
}

func TestWAFTrafficHTTPAndIsolation(t *testing.T) {
	repo := &Repository{}
	repo.publishWAF(smallTrafficPolicy())
	reached := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(204) })
	public := repo.trafficHandler(next, false)
	admin := repo.trafficHandler(next, true)
	call := func(handler http.Handler, method, path, remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("body remains unread"))
		req.RemoteAddr = remote
		req.Header.Set("Range", "bytes=100-")
		req.Header.Set("If-None-Match", `"example"`)
		req.Header.Set("X-Forwarded-For", "198.51.100.5")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	for _, method := range []string{"GET", "HEAD"} {
		if w := call(public, method, "/news/subject.txt", "192.0.2.1:80"); w.Code != 204 {
			t.Fatal(w.Code)
		}
	}
	if w := call(public, "POST", "/", "192.0.2.1:80"); w.Code != 429 || w.Header().Get("Retry-After") != "1" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Header())
	}
	if reached != 2 {
		t.Fatal("rejected request reached handler")
	}
	if w := call(admin, "GET", "/waf", "192.0.2.1:80"); w.Code != 204 {
		t.Fatal("public consumed admin quota", w.Code)
	}
	if w := call(public, "GET", "/", "192.0.2.2:80"); w.Code != 204 {
		t.Fatal("raw XFF grouped different actual sources", w.Code)
	}
	stats := repo.publicTraffic.Stats()
	if stats.RateLimited != 1 || stats.Active != 0 {
		t.Fatal(stats)
	}
	policy := repo.wafSettings()
	policy.Traffic.ClientEnabled = false
	repo.publishWAF(policy)
	for range 5 {
		if w := call(public, "GET", "/", "192.0.2.1:80"); w.Code != 204 {
			t.Fatal("network OFF", w.Code)
		}
	}
	policy.Traffic.Enabled = false
	repo.publishWAF(policy)
	if w := call(public, "GET", "/", "192.0.2.1:80"); w.Code != 204 {
		t.Fatal("traffic OFF", w.Code)
	}
	policy.Traffic.Enabled = true
	policy.Enabled = false
	repo.publishWAF(policy)
	if w := call(public, "GET", "/", "192.0.2.1:80"); w.Code != 204 {
		t.Fatal("master OFF", w.Code)
	}
}

func TestWAFTrafficReleasesOnPanic(t *testing.T) {
	repo := &Repository{}
	repo.publishWAF(smallTrafficPolicy())
	handler := repo.trafficHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("test panic") }), false)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic not propagated")
			}
		}()
		req := httptest.NewRequest("GET", "/search?q=hello", nil)
		req.RemoteAddr = "192.0.2.1:80"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}()
	if stats := repo.publicTraffic.Stats(); stats.Active != 0 || stats.SearchActive != 0 {
		t.Fatal(stats)
	}
}

func TestWAFTrafficStrictSettings(t *testing.T) {
	var policy WAFSettings
	if err := strictjson.Decode([]byte(`{"enabled":true}`), &policy); err != nil || policy.Traffic != waf.DefaultTrafficSettings() {
		t.Fatal(policy, err)
	}
	if wafMinimumReader(json.RawMessage(`{"enabled":true}`)) != 86 {
		t.Fatal("legacy reader")
	}
	good, _ := json.Marshal(smallTrafficPolicy())
	if err := strictjson.Decode(good, &policy); err != nil {
		t.Fatal(err)
	}
	if wafMinimumReader(good) != wafReader {
		t.Fatal("投稿設定を旧readerへ渡した")
	}
	var outer, traffic map[string]json.RawMessage
	_ = json.Unmarshal(good, &outer)
	_ = json.Unmarshal(outer["traffic"], &traffic)
	delete(traffic, "client_enabled")
	outer["traffic"], _ = json.Marshal(traffic)
	oldPosting, _ := json.Marshal(outer)
	if err := strictjson.Decode(oldPosting, &policy); err != nil || !policy.Traffic.ClientEnabled || wafMinimumReader(oldPosting) != 88 {
		t.Fatal("既存ネットワーク制限の互換", err)
	}
	delete(traffic, "posting")
	outer["traffic"], _ = json.Marshal(traffic)
	old, _ := json.Marshal(outer)
	if err := strictjson.Decode(old, &policy); err != nil || policy.Traffic.Posting != waf.DefaultPostingSettings() || wafMinimumReader(old) != 87 {
		t.Fatal("既存の保護/reader境界が変化した", err)
	}
	for _, raw := range []string{
		`{"enabled":true,"traffic":null}`,
		`{"enabled":true,"traffic":{"enabled":true}}`,
		strings.Replace(string(good), `"client_rate":1`, `"client_rate":0`, 1),
		strings.Replace(string(good), `"client_rate":1`, `"client_rate":1,"client_rate":2`, 1),
		strings.Replace(string(good), `"client_rate":1`, `"client_rate":1.0`, 1),
		strings.Replace(string(good), `"global_rate":10`, `"global_rate":0`, 1),
	} {
		if err := strictjson.Decode([]byte(raw), &policy); err == nil {
			t.Fatal("accepted", raw)
		}
	}
}

func TestWAFTrafficAuthenticatedEdgeAndAdmin(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	clientTLS, _ := proxyCertificates(t, &cfg)
	cfg.Admin.Transport, cfg.Admin.Listen, cfg.Admin.Origin = "public_path", "", cfg.Public.BaseURL+"/admin"
	repo.cfg = cfg
	repo.publishWAF(smallTrafficPolicy())
	configured, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(configured.Handler)
	server.Config.ConnContext = configured.ConnContext
	server.TLS = configured.TLSConfig.Clone()
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: clientTLS}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(ip, path, xff string) int {
		req, _ := http.NewRequest("GET", server.URL+path, nil)
		req.Host = "localhost:9080"
		req.Header = edgeTestHeaders()
		req.Header.Set("X-Oimo-Client-IP", ip)
		req.Header.Del("X-Forwarded-For")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode
	}
	for range 2 {
		if status := call("192.0.2.19", "/", "192.0.2.19"); status != 200 {
			t.Fatal(status)
		}
	}
	if status := call("192.0.2.19", "/", ""); status != 429 {
		t.Fatal("same authenticated source", status)
	}
	if status := call("192.0.2.20", "/", ""); status != 200 {
		t.Fatal("edge peer counted instead of client", status)
	}
	if status := call("192.0.2.19", "/", "192.0.2.21"); status != 400 {
		t.Fatal("forged forwarding", status)
	}
	if status := call("192.0.2.19", "/admin/login", ""); status != 200 {
		t.Fatal("admin quota shared", status)
	}
	if stats := repo.publicTraffic.Stats(); stats.RateLimited != 1 || stats.Active != 0 {
		t.Fatal(stats)
	}
	if stats := repo.adminTraffic.Stats(); stats.Clients != 1 || stats.Active != 0 {
		t.Fatal(stats)
	}
}

// 制限枠の確認を文字列検査より先に行い、同じ攻撃の繰返しで重い検査を続けない。
func TestWAFTrafficLimitsBeforeInspection(t *testing.T) {
	repo := &Repository{}
	repo.publishWAF(smallTrafficPolicy())
	handler := repo.trafficHandler(repo.wafHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("attack reached route") })), false)
	for index, want := range []int{403, 403, 429} {
		req := httptest.NewRequest("POST", "/.git/config", nil)
		req.RemoteAddr = "192.0.2.1:80"
		req.Body = io.NopCloser(wafTrapReader{})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatal(index, w.Code, want)
		}
	}
	if repo.wafBlocked.Load() != 2 {
		t.Fatal("rejected flood still inspected", repo.wafBlocked.Load())
	}
}

type wafTrapReader struct{}

func (wafTrapReader) Read([]byte) (int, error) { panic("rejected request body was read") }

func TestWAFOperationAliasesAndUnreadRejection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		admin bool
		base  string
		paths []string
		burst int
	}{
		{"posting", false, "", []string{"/test/bbs.cgi", "/web/post?bbs=news"}, 30},
		{"reports", false, "", []string{"/reports", "/reports/lookup"}, 6},
		{"auth-direct", true, "", []string{"/login", "/reauth", "/api/v1/reauth"}, 3},
		{"passkey-auth", true, "/admin", []string{"/admin/api/v1/passkey/login/begin", "/admin/api/v1/passkey/login/finish", "/admin/api/v1/passkey/reauth/begin", "/admin/api/v1/passkey/register/begin"}, 3},
		{"auth-mounted", true, "/admin", []string{"/admin/login", "/admin/reauth", "/admin/api/v1/reauth"}, 3},
		{"auth-custom-mounted", true, "/control-secret-123456", []string{"/control-secret-123456/login", "/control-secret-123456/reauth", "/control-secret-123456/api/v1/reauth"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &Repository{}
			if tc.base != "" {
				repo.cfg.Admin.Transport = "public_path"
				repo.cfg.Admin.Origin = "https://example.invalid" + tc.base
			}
			repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
			reached := 0
			handler := repo.trafficHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(204) }), tc.admin)
			for n := range tc.burst + 1 {
				req := httptest.NewRequest("POST", tc.paths[n%len(tc.paths)], nil)
				req.RemoteAddr = "192.0.2.1:80"
				req.Body = io.NopCloser(wafTrapReader{})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				want := 204
				if n == tc.burst {
					want = 429
				}
				if w.Code != want {
					t.Fatalf("request %d: %d != %d", n, w.Code, want)
				}
				if want == 429 && (w.Header().Get("Retry-After") != "1" || w.Header().Get("Cache-Control") != "no-store") {
					t.Fatal(w.Header())
				}
			}
			if reached != tc.burst {
				t.Fatal("rejection reached handler", reached)
			}
			path := "/news/subject.txt"
			if tc.admin {
				path = tc.base + "/waf"
			}
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "192.0.2.1:80"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != 204 {
				t.Fatal("normal reading affected", w.Code)
			}
		})
	}
}

func TestWAFOperationRouteBoundary(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		admin        bool
		base         string
		want         waf.Operation
	}{
		{"GET", "/search?q=hello", false, "", waf.Search},
		{"GET", "/reports", false, "", waf.Reports},
		{"GET", "/web/post?bbs=news", false, "", waf.Ordinary},
		{"POST", "/web/post?bbs=news", false, "", waf.Posting},
		{"POST", "/login", false, "", waf.Ordinary},
		{"GET", "/login", true, "", waf.Ordinary},
		{"POST", "/api/v1/reauth", true, "", waf.Authentication},
		{"POST", "/api/v1/otp/login", true, "", waf.Authentication},
		{"GET", "/admin/api/v1/otp/register/qr", true, "/admin", waf.Authentication},
		{"POST", "/admin/api/v1/otp/reauth", true, "/admin", waf.Authentication},
		{"POST", "/password", true, "", waf.Authentication},
		{"POST", "/admin/api/v1/password", true, "/admin", waf.Authentication},
		{"POST", "/administrators/target/password-reset", true, "", waf.Authentication},
		{"POST", "/admin/api/v1/administrators/target/password-reset", true, "/admin", waf.Authentication},
		{"POST", "/api/v1/otp/login", false, "", waf.Ordinary},
		{"POST", "/api/v1/passkey/login/begin", true, "", waf.Authentication},
		{"POST", "/admin/api/v1/passkey/login/finish", true, "/admin", waf.Authentication},
		{"POST", "/admin/api/v1/passkey/reauth/finish", true, "/admin", waf.Authentication},
		{"POST", "/api/v1/passkey/login/begin", false, "", waf.Ordinary},
		{"GET", "/api/v1/passkey/login/begin", true, "", waf.Ordinary},
		{"POST", "/control/reauth", true, "/control", waf.Authentication},
		{"POST", "/other/reauth", true, "/control", waf.Ordinary},
		{"POST", "/control/login/extra", true, "/control", waf.Ordinary},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if got := wafOperation(req, tc.admin, tc.base); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
}

// 実サーバーの経路で、削除依頼のフォーム表示と公開パスの管理認証に追加枠が届くことを検証する。
func TestWAFOperationRealHTTP(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Transport, repo.cfg.Admin.Listen = "public_path", ""
	repo.cfg.Admin.Origin = repo.cfg.Public.BaseURL + "/admin"
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
	server := wafPublicServer(t, repo)
	server.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	call := func(method, path string) int {
		req, _ := http.NewRequest(method, server.URL+path, nil)
		req.Host = "127.0.0.1:9080"
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode
	}
	for range 6 {
		if status := call("GET", "/reports"); status != 200 {
			t.Fatal("report form", status)
		}
	}
	if status := call("POST", "/reports/lookup"); status != 429 {
		t.Fatal("report alias", status)
	}
	for _, path := range []string{"/admin/login", "/admin/reauth", "/admin/api/v1/reauth"} {
		if status := call("POST", path); status == 429 || status == 503 {
			t.Fatal("auth warmup", status)
		}
	}
	if status := call("POST", "/admin/login"); status != 429 {
		t.Fatal("mounted authentication", status)
	}
	if status := call("GET", "/admin/login"); status != 200 {
		t.Fatal("admin page affected", status)
	}
	if status := call("GET", "/"); status != 200 {
		t.Fatal("normal page affected", status)
	}
}
