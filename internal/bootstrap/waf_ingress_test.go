// Host・宣言本文長の軽量拒否を、本文読取りと共有の頻度枠より先に行うことを確認する。
package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/waf"
	"testing"
)

func TestWAFIngressRejectsBeforeBodyAndTraffic(t *testing.T) {
	repo := &Repository{}
	policy := smallTrafficPolicy()
	repo.publishWAF(policy)
	origin, _ := url.Parse("https://forum.example")
	calls := 0
	handler := repo.wafIngressHandler(repo.trafficHandler(repo.wafHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(204) })), false), origin, 64<<10)
	for _, host := range []string{"localhost", "127.0.0.1", "internal-admin", "forum.example.evil", "forum.example@evil", "forum.example:80"} {
		req := httptest.NewRequest("POST", "/test/bbs.cgi", nil)
		req.Host = host
		req.RemoteAddr = "192.0.2.1:8000"
		req.ContentLength = 1
		body := &wafQueryBody{}
		req.Body = body
		req.Header.Set("X-Forwarded-Host", "forum.example")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 403 || body.reads != 0 || calls != 0 || w.Header().Get("Connection") != "close" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(host, w.Code, body.reads, calls)
		}
	}
	lookalike, _ := url.Parse("https://k.example")
	if wafHostMatches("K.example", lookalike) {
		t.Fatal("Unicode lookalike bypassed ASCII origin policy")
	}
	for _, size := range []int64{(64 << 10) + 1, 999999999999, -2} {
		req := httptest.NewRequest("POST", "/test/bbs.cgi", nil)
		req.Host = "forum.example"
		req.RemoteAddr = "192.0.2.1:8000"
		req.ContentLength = size
		body := &wafQueryBody{}
		req.Body = body
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 403 || body.reads != 0 || calls != 0 {
			t.Fatal(size, w.Code, body.reads, calls)
		}
	}
	if stats := repo.publicTraffic.Stats(); stats.Clients != 0 || stats.Active != 0 {
		t.Fatal("invalid ingress consumed traffic state", stats)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "forum.example"
	req.RemoteAddr = "192.0.2.1:8000"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 204 || calls != 1 {
		t.Fatal("normal request blocked", w.Code, calls)
	}
	repo.publishWAF(WAFSettings{Traffic: waf.DefaultTrafficSettings()})
	req.Host = "other.invalid"
	req.ContentLength = 999999999999
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 204 || calls != 2 {
		t.Fatal("OFF boundary changed", w.Code, calls)
	}
}

func TestWAFIngressAllowsConfiguredAuthorities(t *testing.T) {
	for _, tc := range []struct {
		origin string
		hosts  []string
	}{
		{"https://forum.example", []string{"forum.example", "FORUM.EXAMPLE", "forum.example:443"}},
		{"https://forum.example:8443", []string{"forum.example:8443", "FORUM.EXAMPLE:8443"}},
		{"http://127.0.0.1:9080", []string{"127.0.0.1:9080"}},
		{"http://localhost:9080", []string{"localhost:9080", "LOCALHOST:9080"}},
		{"https://[::1]:8443", []string{"[::1]:8443"}},
	} {
		origin, _ := url.Parse(tc.origin)
		repo := &Repository{}
		repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
		h := repo.wafIngressHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), origin, waf.MaxRequestBodyBytes)
		for _, host := range tc.hosts {
			req := httptest.NewRequest("POST", "/", nil)
			req.Host = host
			req.ContentLength = waf.MaxRequestBodyBytes
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != 204 {
				t.Fatal(tc.origin, host, w.Code)
			}
		}
	}
}
