// 中継前の拒否で未送信本文を待たず、HTTP/1の接続を終了することを実TLSで検査する。
package publicedge

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"oimobbs/internal/delivery"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEdgeRejectsUnreceivedBody(t *testing.T) {
	upstream, _ := url.Parse("https://backend.invalid:8443")
	h, err := Handler("https://bbs.example", upstream, transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/unavailable/subject.txt" {
			return nil, fmt.Errorf("upstream unavailable")
		}
		t.Error("拒否要求が転送された")
		return nil, fmt.Errorf("unexpected forwarding")
	}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.Config.ReadTimeout = 10 * time.Second
	server.StartTLS()
	defer server.Close()
	for _, tc := range []struct {
		method, path, host string
		size, status       int
	}{
		{"POST", "/", "foreign.invalid", 65536, 400}, {"POST", "/login", "bbs.example", 65536, 505}, {"PATCH", "/test/bbs.cgi", "bbs.example", 65536, 405}, {"POST", "/test/bbs.cgi", "bbs.example", 65537, 413}, {"POST", "/unavailable/subject.txt", "bbs.example", 65536, 503},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			dialer := &net.Dialer{Timeout: time.Second}
			conn, err := tls.DialWithDialer(dialer, "tcp", server.Listener.Addr().String(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", tc.method, tc.path, tc.host, tc.size); err != nil {
				t.Fatal(err)
			}
			res, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal("中継拒否が本文を待った", err)
			}
			defer res.Body.Close()
			if res.StatusCode != tc.status || !res.Close {
				t.Fatal(res.StatusCode, res.Header)
			}
			if _, err = io.Copy(io.Discard, res.Body); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEdgeRelaysRejectionWithoutReceivingBody(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprint(http2), func(t *testing.T) {
			backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if (r.ProtoMajor == 2) != http2 {
					t.Errorf("保存側のHTTP接続方式が違う: %s", r.Proto)
				}
				delivery.RejectUnreadBody(w, r)
				http.Error(w, "limited", 429)
			}))
			backend.EnableHTTP2 = http2
			backend.StartTLS()
			defer backend.Close()
			target, _ := url.Parse(backend.URL)
			transport := backend.Client().Transport.(*http.Transport).Clone()
			transport.ForceAttemptHTTP2 = http2
			defer transport.CloseIdleConnections()
			h, err := Handler("https://bbs.example", target, transport)
			if err != nil {
				t.Fatal(err)
			}
			front := httptest.NewUnstartedServer(h)
			front.Config.ReadTimeout = 10 * time.Second
			front.StartTLS()
			defer front.Close()
			config := front.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", front.Listener.Addr().String(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = fmt.Fprint(conn, "POST /test/bbs.cgi HTTP/1.1\r\nHost: bbs.example\r\nContent-Length: 65536\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			res, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal("保存側の拒否が利用者の本文を待った", err)
			}
			defer res.Body.Close()
			if res.StatusCode != 429 || !res.Close {
				t.Fatal(res.StatusCode, res.Header)
			}
			if _, err = io.Copy(io.Discard, res.Body); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEdgeHTTP2RejectionKeepsOtherStreams(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			delivery.RejectUnreadBody(w, r)
			http.Error(w, "limited", 429)
			return
		}
		w.WriteHeader(204)
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	h, err := Handler("https://bbs.example", target, backend.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewUnstartedServer(h)
	front.EnableHTTP2 = true
	front.StartTLS()
	defer front.Close()
	client := front.Client()
	client.Timeout = 2 * time.Second
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	for index, want := range []int{429, 204} {
		method, path := "POST", "/test/bbs.cgi"
		var body io.Reader = reader
		if index == 1 {
			method, path, body = "GET", "/probe/subject.txt", nil
		}
		req, err := http.NewRequest(method, front.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "bbs.example"
		if index == 0 {
			req.ContentLength = 65536
		}
		reused := false
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("HTTP/2の未送信本文で中継拒否が待たされた", err)
		}
		_, err = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != want || res.ProtoMajor != 2 || res.Header.Get("Connection") != "" || index > 0 && !reused {
			t.Fatal(index, res.StatusCode, res.Proto, reused, err)
		}
	}
}

// edgeDeadlineProbe はエラー応答を全て読んだ後だけ受信を停止したか記録する。
type edgeDeadlineProbe struct {
	*httptest.ResponseRecorder
	drained  *atomic.Bool
	deadline time.Time
	early    bool
}

func (w *edgeDeadlineProbe) SetReadDeadline(at time.Time) error {
	w.deadline = at
	w.early = !w.drained.Load()
	return nil
}

type edgeDrainMarker struct {
	*strings.Reader
	drained *atomic.Bool
}

func (r *edgeDrainMarker) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		r.drained.Store(true)
	}
	return n, err
}

type edgeRequestBody struct {
	io.Reader
	closed int
}

func (r *edgeRequestBody) Close() error { r.closed++; return nil }

func TestEdgeStopsReceivingAfterForwardingError(t *testing.T) {
	var drained atomic.Bool
	upstream, _ := url.Parse("https://backend.invalid")
	h, err := Handler("https://bbs.example", upstream, transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Header: http.Header{}, Body: io.NopCloser(&edgeDrainMarker{Reader: strings.NewReader("complete error"), drained: &drained}), Request: r}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "https://bbs.example/test/bbs.cgi", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.ContentLength = 65536
	body := &edgeRequestBody{Reader: strings.NewReader("")}
	req.Body = body
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}))
	w := &edgeDeadlineProbe{ResponseRecorder: httptest.NewRecorder(), drained: &drained}
	h.ServeHTTP(w, req)
	if w.Code != 429 || w.Body.String() != "complete error" || w.Header().Get("Connection") != "close" || w.deadline.IsZero() || w.early || body.closed != 1 {
		t.Fatal(w.Code, w.Header(), w.Body.String(), w.deadline, w.early, body.closed)
	}
}
