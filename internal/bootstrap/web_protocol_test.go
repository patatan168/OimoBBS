// 公開・直接HTTPS管理の旧HTTP拒否が、未送信本文を待たずに完了することを検査する。
package bootstrap

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPublicAndDirectAdminRejectHTTP1BeforeBody(t *testing.T) {
	repo, roots := publicAdminFixture(t)
	for _, admin := range []bool{false, true} {
		t.Run(fmt.Sprintf("admin=%t", admin), func(t *testing.T) {
			configured, err := repo.ValidationHTTPServer()
			origin, _ := url.Parse(repo.cfg.Public.BaseURL)
			if admin {
				configured, err = repo.AdminHTTPServer()
				origin, _ = url.Parse(repo.cfg.Admin.Origin)
			}
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(configured.Handler)
			server.Config = configured
			server.TLS = configured.TLSConfig.Clone()
			server.StartTLS()
			defer server.Close()
			for _, version := range []string{"HTTP/1.0", "HTTP/1.1"} {
				for _, path := range []string{"/", "/login", "/web/assets/ui.js", "/web/post", "/missing"} {
					for _, method := range []string{"GET", "HEAD", "POST", "PATCH"} {
						conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "localhost"})
						if err != nil {
							t.Fatal(err)
						}
						_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
						_, err = fmt.Fprintf(conn, "%s %s %s\r\nHost: %s\r\nAccept-Encoding: gzip\r\nContent-Length: 65536\r\n\r\n", method, path, version, origin.Host)
						if err != nil {
							conn.Close()
							t.Fatal(err)
						}
						res, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
						if err != nil {
							conn.Close()
							t.Fatal("protocol rejection waited for body", err)
						}
						body, err := io.ReadAll(res.Body)
						res.Body.Close()
						conn.Close()
						if err != nil || res.StatusCode != 505 || len(body) != 0 || !res.Close || len(res.Cookies()) != 0 || res.Header.Get("Cache-Control") != "no-store" {
							t.Fatal(method, path, version, res.Status, res.Header, err)
						}
					}
				}
			}
		})
	}
}

// TestLegacyHTTP1PublicContracts は実TLSの公開組立てで専ブラの投稿・Cookie・配信契約を通す。
func TestLegacyHTTP1PublicContracts(t *testing.T) {
	repo, roots := publicAdminFixture(t)
	if _, err := repo.CreateBoard(t.Context(), "protocol", "HTTP世代試験"); err != nil {
		t.Fatal(err)
	}
	configured, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(configured.Handler)
	server.Config = configured
	server.TLS = configured.TLSConfig.Clone()
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{DisableCompression: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 3 * time.Second}
	origin, _ := url.Parse(repo.cfg.Public.BaseURL)
	request := func(method, path, body string, headers http.Header) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		req.Host = origin.Host
		if headers != nil {
			req.Header = headers.Clone()
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.ProtoMajor != 1 {
			t.Fatal("legacy protocol/body", res.Proto, err)
		}
		return res, string(raw)
	}
	fields := url.Values{"bbs": {"protocol"}, "subject": {"HTTP1 thread"}, "MESSAGE": {"legacy body"}, "oimo_request_id": {"http1-legacy-contract"}}
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"}}
	res, body := request("POST", "/test/bbs.cgi", fields.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(body, "<!-- 2ch_X:cookie -->") {
		t.Fatal("legacy confirmation", res.Status, body)
	}
	res, body = request("POST", "/test/bbs.cgi", fields.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(body, "/test/read.cgi/protocol/") {
		t.Fatal("legacy durable posting", res.Status, body)
	}
	res, subject := request("GET", "/protocol/subject.txt", "", nil)
	if res.StatusCode != 200 || !strings.Contains(subject, "HTTP1 thread") {
		t.Fatal("legacy subject", res.Status, subject)
	}
	dat := "/protocol/dat/" + strings.Split(subject, "<>")[0]
	for _, path := range []string{"/bbsmenu.html", "/bbsmenu.json", "/protocol/subject.txt", "/protocol/SETTING.TXT", "/protocol/head.txt", dat} {
		res, _ := request("GET", path, "", http.Header{"Accept-Encoding": {"identity"}})
		if res.StatusCode != 200 || res.Header.Get("Content-Encoding") != "" || res.Header.Get("ETag") == "" {
			t.Fatal("legacy identity", path, res.Status, res.Header)
		}
		unchanged, body := request("GET", path, "", http.Header{"If-None-Match": {res.Header.Get("ETag")}})
		if unchanged.StatusCode != 304 || body != "" {
			t.Fatal("legacy conditional", path, unchanged.Status)
		}
	}
	res, full := request("GET", dat, "", nil)
	if res.StatusCode != 200 || len(full) <= 5 {
		t.Fatal("legacy DAT", res.Status, full)
	}
	res, delta := request("GET", dat, "", http.Header{"Range": {"bytes=5-"}})
	if res.StatusCode != 206 || res.Header.Get("Content-Encoding") != "" || delta != full[5:] {
		t.Fatal("legacy range", res.Status, res.Header)
	}
	res, head := request("HEAD", dat, "", nil)
	if res.StatusCode != 200 || head != "" || res.ContentLength != int64(len(full)) {
		t.Fatal("legacy HEAD", res.Status, res.ContentLength)
	}
}
