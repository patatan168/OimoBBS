// HTTP/1・HTTP/2の実socket、HEAD/304/エラーと帯域待ち後の失効を検査する。
package delivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAllHTTPResponsesUseBudget(t *testing.T) {
	for _, test := range []struct {
		method string
		status int
		body   string
	}{{"GET", 200, "hello"}, {"HEAD", 200, ""}, {"GET", 304, ""}, {"GET", 503, "busy"}, {"GET", 302, ""}} {
		t.Run(test.method+http.StatusText(test.status), func(t *testing.T) {
			s, e := New(1)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			request := httptest.NewRequest(test.method, "http://example.test/", nil)
			request.RemoteAddr = "192.0.2.1:1234"
			recorder := httptest.NewRecorder()
			s.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Budget", "header")
				w.WriteHeader(test.status)
				if test.body != "" {
					_, _ = io.WriteString(w, test.body)
				}
			})).ServeHTTP(recorder, request)
			if recorder.Code != test.status || recorder.Body.String() != test.body {
				t.Fatal(recorder.Code, recorder.Body.String())
			}
			s.mu.Lock()
			charged := burstBytes(s.rate)*8*uint64(time.Second) - s.tokens
			s.mu.Unlock()
			if charged < uint64(256+len(test.body))*8*uint64(time.Second)-uint64(time.Second) {
				t.Fatal("headers/body bypassed budget", charged)
			}
		})
	}
}

func TestHTTPBudgetExhaustionAbortsSocket(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP1", true: "HTTP2"}[http2], func(t *testing.T) {
			s, e := New(1)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			server := httptest.NewUnstartedServer(s.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				// handlerがWriteエラーを無視しても正常な応答終端に読み替えない。
				_, _ = w.Write(bytes.Repeat([]byte("x"), 2*burst))
			})))
			server.EnableHTTP2 = http2
			if http2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			client := server.Client()
			client.Timeout = 3 * time.Second
			response, e := client.Get(server.URL)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			body, e := io.ReadAll(response.Body)
			if e == nil || len(body) >= burst {
				t.Fatal("unlimited or successful truncated response", len(body), e)
			}
			if (response.ProtoMajor == 2) != http2 {
				t.Fatal("wrong protocol", response.Proto)
			}
		})
	}
}

func TestLeaseCheckedAfterBandwidthWait(t *testing.T) {
	s, e := New(80000000)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.mu.Lock()
	s.tokens = 0
	s.mu.Unlock()
	recorder := httptest.NewRecorder()
	w := &Response{ResponseWriter: recorder, scheduler: s, ip: netip.MustParseAddr("192.0.2.1"), ctx: context.Background()}
	gone := errors.New("lease invalidated while waiting")
	checks := 0
	n, e := w.WriteChecked([]byte("private old body"), func() error { checks++; return gone })
	if !errors.Is(e, gone) || n != 0 || checks != 1 || recorder.Body.Len() != 0 || w.started {
		t.Fatal("stale body/headers sent", n, e, checks, recorder.Body.String())
	}
}

func TestRequestGateReleaseAndHeaderBound(t *testing.T) {
	gate, e := NewRequestGate(2, 1)
	if e != nil {
		t.Fatal(e)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	handler := gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		w.WriteHeader(200)
	}))
	done := make(chan struct{})
	request := func(ip string) *http.Request {
		r := httptest.NewRequest("GET", "http://example.test", nil)
		r.RemoteAddr = net.JoinHostPort(ip, "1234")
		return r
	}
	go func() { handler.ServeHTTP(httptest.NewRecorder(), request("192.0.2.1")); close(done) }()
	<-started
	refused := httptest.NewRecorder()
	handler.ServeHTTP(refused, request("::ffff:192.0.2.1"))
	if refused.Code != 503 {
		t.Fatal("mapped IP bypassed admission", refused.Code)
	}
	r := request("192.0.2.1")
	refused = httptest.NewRecorder()
	handler.ServeHTTP(refused, r)
	if refused.Code != 503 {
		t.Fatal(refused.Code)
	}
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, request("192.0.2.2"))
	if allowed.Code != 200 {
		t.Fatal(allowed.Code)
	}
	close(release)
	<-done
	allowed = httptest.NewRecorder()
	handler.ServeHTTP(allowed, request("192.0.2.1"))
	if allowed.Code != 200 {
		t.Fatal("slot leaked", allowed.Code)
	}
	r = request("192.0.2.1")
	r.Header.Set("X-Large", strings.Repeat("x", 16<<10))
	refused = httptest.NewRecorder()
	handler.ServeHTTP(refused, r)
	if refused.Code != 431 {
		t.Fatal(refused.Code)
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.total != 0 || len(gate.ips) != 0 {
		t.Fatal("request map retained")
	}
}
