// 投稿HTTP入口のHost・origin・重複Cookieを、本文を読む前に拒否する。
package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"strings"
	"testing"
)

func TestLegacyRequestBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*http.Request)
		valid  bool
	}{
		{"client_without_origin", func(r *http.Request) {}, true},
		{"same_origin", func(r *http.Request) { r.Header.Set("Origin", "https://example.test") }, true},
		{"default_port", func(r *http.Request) { r.Host = "EXAMPLE.TEST:443"; r.Header.Set("Origin", "https://EXAMPLE.TEST:443") }, true},
		{"referer", func(r *http.Request) { r.Header.Set("Referer", "https://example.test/thread?private=value") }, true},
		{"wrong_host", func(r *http.Request) { r.Host = "evil.test" }, false},
		{"wrong_port", func(r *http.Request) { r.Host = "example.test:444" }, false},
		{"plaintext", func(r *http.Request) { r.TLS = nil }, false},
		{"foreign_origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }, false},
		{"null_origin", func(r *http.Request) { r.Header.Set("Origin", "null") }, false},
		{"origin_path", func(r *http.Request) { r.Header.Set("Origin", "https://example.test/path") }, false},
		{"origin_userinfo", func(r *http.Request) { r.Header.Set("Origin", "https://secret@example.test") }, false},
		{"foreign_referer", func(r *http.Request) { r.Header.Set("Referer", "https://evil.test/path") }, false},
		{"cross_site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, false},
		{"same_site_without_origin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, false},
		{"browser_without_origin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "none") }, false},
		{"same_origin_browser", func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("Origin", "https://example.test")
		}, true},
		{"same_site_with_origin", func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Site", "same-site")
			r.Header.Set("Origin", "https://example.test")
		}, false},
		{"duplicate_origin", func(r *http.Request) { r.Header["Origin"] = []string{"https://example.test", "https://example.test"} }, false},
		{"mixed_case_duplicates", func(r *http.Request) {
			r.Header["Origin"] = []string{"https://example.test"}
			r.Header["origin"] = []string{"https://example.test"}
		}, false},
		{"duplicate_cookie", func(r *http.Request) {
			r.Header.Add("Cookie", "oimo_confirm=one")
			r.Header.Add("Cookie", "oimo_confirm=two")
		}, false},
		{"malformed_cookie", func(r *http.Request) { r.Header.Set("Cookie", "oimo_confirm") }, false},
		{"duplicate_type", func(r *http.Request) { r.Header.Add("Content-Type", "application/x-www-form-urlencoded") }, false},
		{"get", func(r *http.Request) { r.Method = "GET" }, false},
		{"encoded_path", func(r *http.Request) { r.URL.RawPath = "/test/%62bs.cgi" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://example.test/test/bbs.cgi", strings.NewReader("body"))
			r.TLS = &tls.ConnectionState{}
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			tc.modify(r)
			_, e := checkLegacyRequest(r, "https://example.test")
			if (e == nil) != tc.valid {
				t.Fatal(e)
			}
		})
	}
}

func TestRejectedHTTPBoundaryDoesNotPersist(t *testing.T) {
	cfg := testConfig(t)
	report, e := Initialize(cfg, "境界試験")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	board, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, repo, report.SiteID, board.ID)
	defer server.Close()
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"host", func(r *http.Request) { r.Host = "evil.test" }},
		{"origin", func(r *http.Request) { r.Header.Set("Origin", "http://evil.test") }},
		{"referer", func(r *http.Request) { r.Header.Set("Referer", "http://evil.test/private") }},
		{"cross_site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"same_site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
		{"browser_without_origin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "none") }},
		{"duplicate_cookie", func(r *http.Request) { r.Header.Add("Cookie", "oimo_confirm=one; oimo_confirm=two") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", server.URL+"/test/bbs.cgi", strings.NewReader("bbs=news&subject=title&MESSAGE=body"))
			req.Host = "127.0.0.1:9080"
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			tc.change(req)
			response, e := server.Client().Do(req)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			var result formResult
			if e = json.NewDecoder(response.Body).Decode(&result); e != nil {
				t.Fatal(e)
			}
			if response.StatusCode != 400 || result.Accepted || result.Confirmation != nil || len(response.Cookies()) != 0 {
				t.Fatal("rejected request progressed", result)
			}
		})
	}
	b := repo.posting[board.ID]
	if len(b.threads) != 0 || len(b.journals) != 0 || b.control.State().Seq != 1 {
		t.Fatal("rejected request wrote data")
	}
	fields := url.Values{"bbs": {"news"}, "subject": {"題"}, "MESSAGE": {"本文"}}
	result, e := sendForm(server, fields)
	if e != nil || !result.Accepted {
		t.Fatal("legacy client rejected", result, e)
	}
}

// rejectedBody は境界拒否が本文読取りより先であることを観測する。
type rejectedBody struct{ reads int }

func (b *rejectedBody) Read(p []byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *rejectedBody) Close() error               { return nil }
func TestBoundaryRejectsBeforeObservationAndRead(t *testing.T) {
	repo := &Repository{cfg: Config{Public: PublicConfig{BaseURL: "http://127.0.0.1:9080"}}}
	r := httptest.NewRequest("POST", "http://evil.test/test/bbs.cgi", nil)
	body := &rejectedBody{}
	r.Body = body
	result := repo.SubmitLegacyRequest(r, domain.ID{1}, nil)
	if !errors.Is(result.Err, ErrPostingRequest) || body.reads != 0 {
		t.Fatal("boundary checked too late", result.Err, body.reads)
	}
}

func TestWebOriginRequired(t *testing.T) {
	for _, tc := range []struct {
		origin, referer string
		ok              bool
	}{
		{"", "", false}, {"http://example.test", "", true}, {"", "http://example.test/thread?secret=x", true},
		{"", "http://evil.test/thread", false}, {"null", "http://example.test/", false},
	} {
		r := httptest.NewRequest("POST", "http://example.test/web/post", strings.NewReader("csrf=value"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.referer != "" {
			r.Header.Set("Referer", tc.referer)
		}
		_, e := checkPostingRequest(r, "http://example.test", true)
		if (e == nil) != tc.ok {
			t.Fatal(tc, e)
		}
	}
}
