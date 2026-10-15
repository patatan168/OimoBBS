// WAFの遮断条件と、日本語・技術的な投稿・専ブラ通信の許可境界を検証する。
package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestInspectAttackRequests(t *testing.T) {
	for _, target := range []string{
		"/.git/config", "/.env", "/.env.production", "/x/%2e%2e/etc/passwd", "/x/%252e%252e%252fetc/passwd",
		"/cgi-bin/..%5c..%5cetc/passwd", "/x?x=1+UNION+SELECT+password", "/x?x=%3Cscript%3Ealert(1)%3C/script%3E",
		"/x?x=javascript:alert(1)", "/x?x=%3Bcurl+https://example.invalid/",
	} {
		t.Run(target, func(t *testing.T) {
			r := httptest.NewRequest("GET", target, nil)
			if Inspect(r) == "" {
				t.Fatal("attack passed")
			}
		})
	}
	for _, method := range []string{"TRACE", "CONNECT", "TRACK"} {
		r := httptest.NewRequest(method, "/", nil)
		if Inspect(r) == "" {
			t.Fatal(method)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "${jndi:ldap://example.invalid/a}")
	if Inspect(r) == "" {
		t.Fatal("header injection passed")
	}
}

func TestInspectNormalTrafficAndUntouchedBody(t *testing.T) {
	for _, target := range []string{"/", "/bbsmenu.html", "/news/subject.txt", "/news/dat/123.dat", "/test/read.cgi/news/123/l50", "/search?q=UNION+SELECT", "/search?q=%3Cscript%3E", "/search?q=100%25", "/admin/waf", "/admin/api/v1/waf"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Header.Set("Range", "bytes=100-")
		if got := Inspect(r); got != "" {
			t.Fatal(target, got)
		}
	}
	body := "bbs=news&MESSAGE=" + strings.Repeat("SQL UNION SELECT <script> 日本語 ${jndi:ldap://example.invalid} ", 100)
	r := httptest.NewRequest("POST", "/test/bbs.cgi", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := Inspect(r); got != "" {
		t.Fatal(got)
	}
	after, err := io.ReadAll(r.Body)
	if err != nil || string(after) != body {
		t.Fatal("body consumed or modified", err)
	}
}

func TestInspectionLimits(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?x="+strings.Repeat("a", maxInspectionBytes), nil)
	if got := Inspect(r); got != "url_size" {
		t.Fatal(got)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Test", strings.Repeat("a", maxInspectionBytes))
	if got := Inspect(r); got != "header_size" {
		t.Fatal(got)
	}
}

// FuzzInspectPathFast は高速経路でも従来の正規表現の検出を取りこぼさないことを確認する。
func FuzzInspectPathFast(f *testing.F) {
	for _, path := range []string{"/news/dat/123.dat", "/.env.", "/x/UNION SELECT/a", "/javascript:alert(1)", "/x;sleep(1)", "/x;curl x", "/x\vUNION\tSELECT", "/x/<script>", "/x/ſleep(1)", "/x\\..\\.git"} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > maxInspectionBytes/3 {
			t.Skip()
		}
		req := &http.Request{Method: "GET", URL: &url.URL{Path: path}, Header: make(http.Header)}
		normalized := normalize(req.URL.EscapedPath())
		if (badPath(normalized) || injection.MatchString(normalized)) && Inspect(req) == "" {
			t.Fatalf("missed %q", path)
		}
	})
}
