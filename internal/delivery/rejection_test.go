// 早期拒否の受信期限とHTTP/2・本文なし要求の接続再利用を検査する。
package delivery

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type rejectionDeadlineWriter struct {
	*httptest.ResponseRecorder
	deadline time.Time
	err      error
}

func (w *rejectionDeadlineWriter) SetReadDeadline(at time.Time) error { w.deadline = at; return w.err }

func TestRejectUnreadBodyProtocolBoundary(t *testing.T) {
	for _, tc := range []struct {
		name           string
		proto          int
		length         int64
		chunked, close bool
	}{
		{"fixed", 1, 64, false, true}, {"chunked", 1, -1, true, true}, {"empty", 1, 0, false, false}, {"http2", 2, 64, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", nil)
			r.ProtoMajor = tc.proto
			r.ContentLength = tc.length
			if tc.chunked {
				r.TransferEncoding = []string{"chunked"}
			}
			w := &rejectionDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
			before := time.Now()
			RejectUnreadBody(w, r)
			if (w.Header().Get("Connection") == "close") != tc.close || w.deadline.IsZero() == tc.close {
				t.Fatal(w.Header(), w.deadline)
			}
			if tc.close && (w.deadline.Before(before) || w.deadline.After(time.Now())) {
				t.Fatal("受信期限が即時でない")
			}
		})
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader("body"))
	unsupported := httptest.NewRecorder()
	RejectUnreadBody(unsupported, r)
	if unsupported.Header().Get("Connection") != "close" {
		t.Fatal(unsupported.Header())
	}
	w := &rejectionDeadlineWriter{ResponseRecorder: httptest.NewRecorder(), err: errors.New("closed socket")}
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Fatal("期限設定の実エラーで送信を続けた")
		}
	}()
	RejectUnreadBody(w, r)
}

func TestRequestGateRejectsUnreceivedBody(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(fmt.Sprint(stopped), func(t *testing.T) {
			gate, _ := NewRequestGate(1, 1)
			entered, release := make(chan struct{}), make(chan struct{})
			server := httptest.NewUnstartedServer(gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { close(entered); <-release; w.WriteHeader(204) })))
			server.Config.ReadTimeout = 10 * time.Second
			server.Start()
			defer server.Close()
			if stopped {
				gate.Close()
			} else {
				done := make(chan struct{})
				go func() {
					defer close(done)
					res, err := server.Client().Get(server.URL)
					if err != nil {
						t.Error(err)
						return
					}
					res.Body.Close()
				}()
				<-entered
				defer func() { close(release); <-done }()
			}
			conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: test.invalid\r\nContent-Length: 65536\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			res, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal("本文待ちで503を返せなかった", err)
			}
			defer res.Body.Close()
			if res.StatusCode != 503 || !res.Close {
				t.Fatal(res.StatusCode, res.Header)
			}
			if _, err = io.Copy(io.Discard, res.Body); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeliveryFailureRejectsUnreceivedBody(t *testing.T) {
	scheduler, err := New(80_000_000)
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Close()
	server := httptest.NewUnstartedServer(scheduler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.(*Response).fail(errors.New("test failure")) })))
	server.Config.ReadTimeout = 10 * time.Second
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
	if _, err = fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: test.invalid\r\nContent-Length: 65536\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal("送信予算エラーが未受信本文を待った", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 503 || !res.Close {
		t.Fatal(res.StatusCode, res.Header)
	}
	if _, err = io.Copy(io.Discard, res.Body); err != nil {
		t.Fatal(err)
	}
}
