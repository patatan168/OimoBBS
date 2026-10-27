// 実TCPの不正HTTP、未送信本文の早期拒否と、HTTP/2の接続を共有する正常要求を検証する。
package bootstrap

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"oimobbs/internal/waf"
	"strings"
	"testing"
	"time"
)

func TestWAFIngressRawHTTP(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	if _, err := repo.CreateBoard(t.Context(), "news", "入口検査"); err != nil {
		t.Fatal(err)
	}
	policy := repo.wafSettings()
	policy.Enabled = true
	policy.Traffic.Enabled = false
	repo.publishWAF(policy)
	public, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		configured   *http.Server
		origin, path string
		limit        int
	}{
		{"public", public, repo.cfg.Public.BaseURL, "/news/subject.txt", 64 << 10},
		{"admin", admin, repo.cfg.Admin.Origin, "/login", 256 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(tc.configured.Handler)
			server.Config = tc.configured
			server.Start()
			defer server.Close()
			origin, _ := url.Parse(tc.origin)
			base := "GET " + tc.path + " HTTP/1.1\r\nHost: " + origin.Host + "\r\nConnection: close\r\n"
			tests := []struct {
				name, raw string
				status    int
			}{
				{"valid", base + "\r\n", 200},
				{"ua-limit", base + "User-Agent: " + strings.Repeat("a", 1024) + "\r\n\r\n", 200},
				{"ua-oversize", base + "User-Agent: " + strings.Repeat("a", 1025) + "\r\n\r\n", 403},
				{"header-server-limit", base + "User-Agent: " + strings.Repeat("a", 100<<10) + "\r\n\r\n", 431},
				{"nul", base + "User-Agent: aaa\x00bbb\r\n\r\n", 400},
				{"control", base + "X-Test: aaa\x01bbb\r\n\r\n", 400},
				{"del", base + "X-Test: aaa\x7fbbb\r\n\r\n", 400},
				{"tab-valid", base + "X-Test: aaa\tbbb\r\n\r\n", 200},
				{"duplicate-host", base + "X-Test: \r\nHost: evil.invalid\r\n\r\n", 400},
				{"foreign-host", "GET " + tc.path + " HTTP/1.1\r\nHost: internal-admin\r\nConnection: close\r\n\r\n", 403},
				{"negative-length", base + "Content-Length: -1\r\n\r\n", 400},
				{"overflow-length", base + "Content-Length: 18446744073709551616\r\n\r\n", 400},
				{"declared-limit", "POST " + tc.path + " HTTP/1.1\r\nHost: " + origin.Host + fmt.Sprintf("\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n", tc.limit+1), 403},
				{"declared-huge", "POST " + tc.path + " HTTP/1.1\r\nHost: " + origin.Host + "\r\nContent-Length: 999999999999\r\nExpect: 100-continue\r\n\r\n", 403},
			}
			for _, probe := range tests {
				t.Run(probe.name, func(t *testing.T) {
					response := wafRawResponse(t, server.Listener.Addr().String(), probe.raw)
					if response.StatusCode != probe.status {
						t.Fatal(response.StatusCode, probe.status)
					}
					if probe.status == 403 && response.Header.Get("Cache-Control") != "no-store" {
						t.Fatal("rejection cached")
					}
					if strings.HasPrefix(probe.name, "declared-") && !response.Close {
						t.Fatal("unreceived body kept connection open")
					}
				})
			}
			// HTTPのヘッダ行数には、通常のConnection一行も含める。
			for _, n := range []int{127, 128} {
				response := wafRawResponse(t, server.Listener.Addr().String(), base+strings.Repeat("X-Empty:\r\n", n)+"\r\n")
				want := 200
				if n == 128 {
					want = 403
				}
				if response.StatusCode != want {
					t.Fatal("field count", n, response.StatusCode, want)
				}
			}
			if tc.name == "public" {
				before := repo.wafBlocked.Load()
				body := "bbs=news&subject=chunked&MESSAGE=normal&oimo_request_id=waf-chunked-control-0001"
				raw := "POST /test/bbs.cgi HTTP/1.1\r\nHost: " + origin.Host + "\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)
				response := wafRawResponse(t, server.Listener.Addr().String(), raw)
				if response.StatusCode != 200 || repo.wafBlocked.Load() != before {
					t.Fatal("ordinary chunked post blocked", response.StatusCode)
				}
			}
		})
	}
}

// wafRawResponse は本文を送らない拒否も二秒以内に受信し、100 Continueで先送りされないことを確認する。
func wafRawResponse(t *testing.T, address, raw string) *http.Response {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// 巨大なヘッダーでは、書込み完了前にサーバーが431を返して閉じる場合もある。
	_, _ = io.WriteString(conn, raw)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response
}

func TestWAFIngressHTTP2KeepsOtherStreamsUsable(t *testing.T) {
	repo := &Repository{}
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
	origin, _ := url.Parse("https://forum.example")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	handler := repo.wafIngressHandler(repo.wafHandler(next), origin, 64<<10)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	for i, ua := range []string{strings.Repeat("a", 1025), "Monazilla/1.00"} {
		method := "GET"
		var body io.Reader
		if i == 0 {
			method, body = "POST", strings.NewReader(strings.Repeat("b", 2048))
		}
		request, _ := http.NewRequest(method, server.URL+"/news/subject.txt", body)
		request.Host = origin.Host
		request.Header.Set("User-Agent", ua)
		reused := false
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		want := 403
		if i == 1 {
			want = 204
		}
		if response.StatusCode != want || response.ProtoMajor != 2 || response.Header.Get("Connection") != "" || i == 1 && !reused {
			t.Fatal("HTTP/2 connection/normal request", response.StatusCode, response.Proto, reused)
		}
	}
}
