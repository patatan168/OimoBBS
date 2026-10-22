// 管理パスだけがPATCHと大きな設定本文を転送し、公開投稿の制限を緩めないことを検査する。
package publicedge

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAdminPathForwardingKeepsPublicBoundaries(t *testing.T) {
	const base = "/admin"
	u, _ := url.Parse("https://backend:8443")
	h, e := handler("https://bbs.example", u, transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Oimo-Client-IP") != "192.0.2.10" {
			t.Fatal("spoofed client IP")
		}
		if r.Body != nil {
			if _, e := io.ReadAll(r.Body); e != nil {
				t.Fatal(e)
			}
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	}), base)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		method, route string
		size, status  int
	}{
		{"PATCH", base + "/api/v1/site", 0, 200}, {"POST", base + "/boards", 128 << 10, 200},
		{"POST", base + "/boards", 257 << 10, 413}, {"PATCH", "/oimo/", 0, 405},
		{"PATCH", base + "-other/api/v1/site", 0, 405}, {"POST", "/test/bbs.cgi", 65 << 10, 413},
		{"GET", "/api/v1/site", 0, 404}, {"GET", "/login", 0, 404},
	} {
		r := httptest.NewRequest(tc.method, "https://bbs.example"+tc.route, strings.NewReader(strings.Repeat("x", tc.size)))
		r.RemoteAddr = "192.0.2.10:12345"
		r.Header.Set("X-Oimo-Client-IP", "127.0.0.1")
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal(tc.method, tc.route, w.Code, tc.status)
		}
	}
	for _, path := range []string{"/", "/api/1234567890123456", "/_manage-0123456789/child", "/_manage-0123456789?x=1"} {
		if _, e := handler("https://bbs.example", u, nil, path); e == nil {
			t.Fatal("ambiguous mount", path)
		}
	}
}
