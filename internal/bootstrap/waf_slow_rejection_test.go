// 未送信本文がある実HTTP要求でも、頻度拒否を即時に返して接続枠を解放する。
package bootstrap

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"oimobbs/internal/platform"
	"oimobbs/internal/waf"
	"strings"
	"testing"
	"time"
)

func TestWAFTrafficRejectsUnreceivedBody(t *testing.T) {
	for _, admin := range []bool{false, true} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("admin=%t/chunked=%t", admin, chunked), func(t *testing.T) {
				repo := &Repository{}
				repo.publishWAF(smallTrafficPolicy())
				guard := &repo.publicTraffic
				if admin {
					guard = &repo.adminTraffic
				}
				for range 2 {
					release, decision := guard.AcquireOperation(netip.MustParseAddr("127.0.0.1"), waf.Ordinary, trafficNow())
					if decision.Status != 0 {
						t.Fatal(decision)
					}
					release()
				}
				server := httptest.NewUnstartedServer(repo.trafficHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("拒否した要求が業務処理へ到達した") }), admin))
				server.Config.ReadTimeout = 10 * time.Second
				closed := make(chan struct{}, 1)
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateClosed {
						select {
						case closed <- struct{}{}:
						default:
						}
					}
				}
				server.Start()
				defer server.Close()
				conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				framing := "Content-Length: 65536\r\n"
				if chunked {
					framing = "Transfer-Encoding: chunked\r\n"
				}
				_, err = fmt.Fprintf(conn, "POST /test/bbs.cgi HTTP/1.1\r\nHost: test.invalid\r\n%s\r\n", framing)
				if err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					t.Fatal("未送信本文の頻度拒否が待たされた", err)
				}
				defer response.Body.Close()
				if response.StatusCode != 429 || !response.Close || response.Header.Get("Retry-After") == "" {
					t.Fatal(response.StatusCode, response.Header)
				}
				if _, err = io.Copy(io.Discard, response.Body); err != nil {
					t.Fatal(err)
				}
				select {
				case <-closed:
				case <-time.After(2 * time.Second):
					t.Fatal("拒否応答後も本文を待って接続枠を保持した")
				}
				if guard.Stats().Active != 0 {
					t.Fatal("拒否で処理枠が残った")
				}
			})
		}
	}
}

func TestMemoryRejectsUnreceivedBody(t *testing.T) {
	repo := &Repository{}
	repo.memory.Store(&platform.MemoryState{Limit: 128 << 20})
	server := httptest.NewUnstartedServer(repo.memoryHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("容量不足で業務処理を開始した") })))
	server.Config.ReadTimeout = 10 * time.Second
	server.Start()
	defer server.Close()
	response := wafRawResponse(t, server.Listener.Addr().String(), "POST /test/bbs.cgi HTTP/1.1\r\nHost: test.invalid\r\nContent-Length: 65536\r\n\r\n")
	if response.StatusCode != 503 || !response.Close || repo.memoryReserved.Load() != 0 {
		t.Fatal(response.StatusCode, response.Header)
	}
}

func TestWAFTrafficHTTP2RejectionKeepsConnection(t *testing.T) {
	repo := &Repository{}
	settings := waf.DefaultTrafficSettings()
	settings.Posting.ClientBurst = 1
	settings.Posting.ClientRate = 1
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: settings})
	server := httptest.NewUnstartedServer(repo.trafficHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), false))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	for index, want := range []int{204, 429, 204} {
		method, path := "POST", "/test/bbs.cgi"
		var body io.Reader = strings.NewReader("unconsumed body")
		if index == 2 {
			method, path, body = "GET", "/probe/subject.txt", nil
		}
		req, err := http.NewRequest(method, server.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		reused := false
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != want || res.ProtoMajor != 2 || res.Header.Get("Connection") != "" || index > 0 && !reused {
			t.Fatal(index, res.StatusCode, res.Proto, reused, err)
		}
	}
}
