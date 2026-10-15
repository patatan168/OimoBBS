// 公開入口の経路拒否、申告endpoint上書き、転送時の本文・応答保持を検査する。
package publicedge

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPublicEdgeBoundaryAndMetadata(t *testing.T) {
	u, _ := url.Parse("https://backend:8443")
	called := 0
	h, err := Handler("https://bbs.example", u, transportFunc(func(r *http.Request) (*http.Response, error) {
		called++
		if r.Host != "bbs.example" || r.URL.Host != "backend:8443" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Oimo-Client-IP") != "192.0.2.10" || r.Header.Get("X-Oimo-Client-Port") != "12345" || r.Header.Get("X-Oimo-Dest-IP") != "198.51.100.1" || r.Header.Get("X-Oimo-Dest-Port") != "8443" || r.Header.Get("X-Oimo-Edge-Request") == "spoof" || r.Header.Get("X-Oimo-Edge-Time") == "1" {
			t.Fatal("untrusted metadata forwarded")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"original"`}}, Body: io.NopCloser(strings.NewReader("original DAT")), Request: r}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/login", "/api/v1/administrators", "/./login", "/%6cogin", "//login"} {
		r := httptest.NewRequest("GET", "https://bbs.example"+route, nil)
		r.RemoteAddr = "192.0.2.10:12345"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 404 {
			t.Fatal("private or ambiguous route passed")
		}
	}
	if called != 0 {
		t.Fatal("rejected request reached backend")
	}
	r := httptest.NewRequest("GET", "https://bbs.example/oimo/dat/1.dat", nil)
	r.RemoteAddr = "192.0.2.10:12345"
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 8443}))
	for k, v := range map[string]string{"Forwarded": "for=127.0.0.1", "X-Forwarded-For": "127.0.0.1", "X-Oimo-Client-IP": "127.0.0.1", "X-Oimo-Edge-Request": "spoof", "X-Oimo-Edge-Time": "1", "Connection": "X-Oimo-Client-Port"} {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if called != 1 || w.Code != 200 || w.Body.String() != "original DAT" || w.Header().Get("ETag") != `"original"` || w.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatal("body, cache or transport changed")
	}
	r.TLS = nil
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HTTP accepted")
	}
	r.TLS = &tls.ConnectionState{}
	r.Method = "PATCH"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatal("mutation reached public backend")
	}
}

func FuzzCanonicalPublicPath(f *testing.F) {
	for _, s := range []string{"/", "/oimo/dat/1.dat", "/../login", "/%6cogin", "//login", "/\\login"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := url.ParseRequestURI(s)
		if err != nil {
			return
		}
		r := &http.Request{URL: u}
		if canonicalPath(r) && (!strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "//") || strings.ContainsAny(u.Path, "\\\x00") || u.EscapedPath() != u.Path) {
			t.Fatal("ambiguous path accepted")
		}
	})
}

func TestPublicOriginHost(t *testing.T) {
	base, _ := url.Parse("https://bbs.example")
	for _, host := range []string{"bbs.example", "bbs.example:443", "BBS.example"} {
		if !sameOriginHost(host, base) {
			t.Fatal("equivalent HTTPS host rejected", host)
		}
	}
	for _, host := range []string{"other.example", "bbs.example:444", "bbs.example/path", "user@bbs.example", "bbs.example?query", "bbs.example?", "bbs.example#", "bbs.example:"} {
		if sameOriginHost(host, base) {
			t.Fatal("foreign origin accepted", host)
		}
	}
}
