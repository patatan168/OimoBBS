// Web取得の圧縮受入必須化と、専ブラの無圧縮・条件付き取得・差分を検査する。
package bootstrap

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/testutil"
	"testing"
	"time"
)

func TestWebCompressionRequired(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "compress", "圧縮試験")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	result, err := sendForm(form, url.Values{"bbs": {"compress"}, "subject": {"圧縮"}, "MESSAGE": {"本文"}, "oimo_request_id": {"compression-required-create"}})
	if err != nil || !result.Accepted {
		t.Fatal(result, err)
	}
	handler := repo.SiteWebHandler(nil)
	request := func(method, path, accept, condition, span string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, cfg.Public.BaseURL+path, nil)
		r.Header.Set("Accept-Encoding", accept)
		r.Header.Set("If-None-Match", condition)
		r.Header.Set("Range", span)
		r.Header.Set("User-Agent", "Monazilla/1.00")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	before := repo.feedCompression.Status().Builds
	for _, path := range []string{"/", "/compress/", "/search", "/reports", "/web/terms", "/web/post?bbs=compress", "/robots.txt", "/web/assets/ui.js", fmt.Sprintf("/test/read.cgi/compress/%d/", result.Key)} {
		for _, method := range []string{"GET", "HEAD"} {
			w := request(method, path, "", "", "bytes=0-")
			if w.Code != 406 || w.Body.Len() != 0 || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
				t.Fatal("uncompressed Web accepted", path, method, w.Code, w.Header())
			}
		}
	}
	if repo.feedCompression.Status().Builds != before {
		t.Fatal("denial built a response")
	}
	for _, path := range []string{"/bbsmenu.html", "/bbsmenu.json", "/compress/subject.txt", "/compress/SETTING.TXT", "/compress/head.txt", fmt.Sprintf("/compress/dat/%d.dat", result.Key)} {
		w := request("GET", path, "identity", "", "")
		if w.Code != 200 || w.Header().Get("Content-Encoding") != "" {
			t.Fatal("legacy identity denied", path, w.Code)
		}
		if unchanged := request("GET", path, "", w.Header().Get("ETag"), ""); unchanged.Code != 304 {
			t.Fatal("legacy conditional changed", path, unchanged.Code)
		}
	}
	datPath := fmt.Sprintf("/compress/dat/%d.dat", result.Key)
	if w := request("GET", datPath, "identity", "", "bytes=5-"); w.Code != 206 || w.Header().Get("Content-Encoding") != "" {
		t.Fatal("DAT delta changed", w.Code)
	}
	if w := request("GET", "/test/bbs.cgi", "", "", ""); w.Code == 406 {
		t.Fatal("legacy posting was gated")
	}
	for _, accept := range []string{"gzip", "zstd", "gzip;q=0.1,identity;q=1"} {
		w := request("GET", "/", accept, "", "")
		if w.Code != 200 {
			t.Fatal("compressed Web denied", accept, w.Code)
		}
		if c := request("GET", "/", accept, w.Header().Get("ETag"), ""); c.Code != 304 {
			t.Fatal("Web conditional", c.Code)
		}
	}
	for _, accept := range []string{"identity", "br", "gzip;q=0,zstd;q=0"} {
		if w := request("GET", "/", accept, "", ""); w.Code != 406 {
			t.Fatal(accept, w.Code)
		}
	}
}

func TestAdminCompressionBeforeNonce(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	server, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, accept := range []string{"", "identity", "gzip;q=0", "gzip"} {
		req := httptest.NewRequest("GET", cfg.Admin.Origin+"/login", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Accept-Encoding", accept)
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, req)
		if accept == "gzip" {
			if w.Code != 200 || len(w.Result().Cookies()) != 1 {
				t.Fatal("login denied", w.Code)
			}
			continue
		}
		if w.Code != 406 || len(w.Result().Cookies()) != 0 || w.Body.Len() != 0 {
			t.Fatal("uncompressed login issued nonce", accept, w.Code)
		}
	}
}

// TestWebCompressionTLS はHTTP/1.1とHTTP/2で拒否・圧縮・304・HEADを実通信から検証する。
func TestWebCompressionTLS(t *testing.T) {
	repo, roots := publicAdminFixture(t)
	repo.cfg.Admin.Transport, repo.cfg.Admin.Listen, repo.cfg.Admin.Origin = "public_path", "", repo.cfg.Public.BaseURL+"/admin"
	configured, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse(repo.cfg.Public.BaseURL)
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%t", h2), func(t *testing.T) {
			server := httptest.NewUnstartedServer(configured.Handler)
			server.Config.ConnContext = configured.ConnContext
			server.TLS = configured.TLSConfig.Clone()
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			transport := &http.Transport{DisableCompression: true, ForceAttemptHTTP2: h2, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			request := func(method, path string, headers http.Header) (*http.Response, []byte) {
				t.Helper()
				r, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Host = origin.Host
				r.Header = headers
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				wantProto := 1
				if h2 {
					wantProto = 2
				}
				if response.ProtoMajor != wantProto {
					t.Fatal("wrong protocol", response.Proto)
				}
				return response, body
			}
			for _, path := range []string{"/", "/admin/login", "/admin/web/assets/ui.js"} {
				for _, method := range []string{"GET", "HEAD"} {
					response, body := request(method, path, nil)
					if response.StatusCode != 406 || len(body) != 0 || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 {
						t.Fatal("uncompressed Web accepted", method, path, response.Status, response.Header)
					}
				}
			}
			if response, body := request("GET", "/admin/login", http.Header{"Accept-Encoding": {"gzip"}}); response.StatusCode != 200 || len(body) == 0 || len(response.Cookies()) != 1 {
				t.Fatal("mounted login denied", response.Status)
			}
			response, raw := request("GET", "/", http.Header{"Accept-Encoding": {"gzip;q=0.1,identity;q=1"}})
			if response.StatusCode != 200 || response.Header.Get("Content-Encoding") != "" {
				t.Fatal("identity preference changed", response.Status)
			}
			for _, coding := range []string{"gzip", "zstd"} {
				response, body := request("GET", "/", http.Header{"Accept-Encoding": {coding}})
				if response.StatusCode != 200 || response.Header.Get("Content-Encoding") != coding {
					t.Fatal(coding, response.Status, response.Header)
				}
				var decoded []byte
				if coding == "gzip" {
					reader, err := gzip.NewReader(bytes.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					decoded, err = io.ReadAll(reader)
					reader.Close()
					if err != nil {
						t.Fatal(err)
					}
				} else {
					decoded, err = testutil.DecodeZstd(body)
					if err != nil {
						t.Fatal(err)
					}
				}
				if !bytes.Equal(decoded, raw) {
					t.Fatal("decoded body differs", coding)
				}
				etag := response.Header.Get("ETag")
				for _, method := range []string{"GET", "HEAD"} {
					response, body := request(method, "/", http.Header{"Accept-Encoding": {coding}, "If-None-Match": {etag}})
					if response.StatusCode != 304 || len(body) != 0 {
						t.Fatal("conditional response", response.Status)
					}
				}
			}
			response, body := request("GET", "/bbsmenu.json", nil)
			if response.StatusCode != 200 || len(body) == 0 || response.Header.Get("Content-Encoding") != "" {
				t.Fatal("legacy menu denied", response.Status)
			}
		})
	}
}
