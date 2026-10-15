// 公開writerの取消・送信障害・短い書込みを検査し、追加送信とflush迂回を拒否する。
package bootstrap

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/delivery"
)

type publicationFaultWriter struct {
	header           http.Header
	sizes            []int
	headers, flushes int
	short            bool
	failure          error
	afterWrite       func()
}

func (w *publicationFaultWriter) Header() http.Header { return w.header }
func (w *publicationFaultWriter) WriteHeader(int)     { w.headers++ }
func (w *publicationFaultWriter) Write(b []byte) (int, error) {
	w.sizes = append(w.sizes, len(b))
	if w.afterWrite != nil {
		w.afterWrite()
	}
	if w.short {
		return len(b) - 1, nil
	}
	if w.failure != nil {
		return 0, w.failure
	}
	return len(b), nil
}
func (w *publicationFaultWriter) FlushError() error { w.flushes++; return w.failure }

func TestPublicResponseWriteFaults(t *testing.T) {
	for _, mode := range []string{"chunks", "short", "error", "cancel_after_chunk", "cancel_before_send"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writer := &publicationFaultWriter{header: http.Header{}}
			response := &publicResponse{ResponseWriter: writer, ctx: ctx, clock: time.Now}
			body := []byte(strings.Repeat("x", 40000))
			sentinel := errors.New("transport failed")
			var want error
			wantN, wantChunks := len(body), 3
			switch mode {
			case "short":
				writer.short = true
				want = io.ErrShortWrite
				wantN, wantChunks = (16<<10)-1, 1
			case "error":
				writer.failure = sentinel
				want = sentinel
				wantN, wantChunks = 0, 1
			case "cancel_after_chunk":
				writer.afterWrite = cancel
				want = context.Canceled
				wantN, wantChunks = 16<<10, 1
			case "cancel_before_send":
				cancel()
				want = context.Canceled
				wantN, wantChunks = 0, 0
			}
			n, err := response.Write(body)
			if !errors.Is(err, want) || n != wantN || len(writer.sizes) != wantChunks {
				t.Fatalf("Write = (%d,%v), chunks %v", n, err, writer.sizes)
			}
			for _, size := range writer.sizes {
				if size > 16<<10 {
					t.Fatal("unchecked oversized send", size)
				}
			}
			if mode == "cancel_before_send" && writer.headers != 0 {
				t.Fatal("cancelled writer sent headers")
			}
			if want == context.Canceled {
				if err := http.NewResponseController(response).Flush(); !errors.Is(err, want) || writer.flushes != 0 {
					t.Fatal("cancelled flush bypassed check", err, writer.flushes)
				}
			}
			response.Close()
			response.Close()
		})
	}
}

func TestPublicResponseFlushError(t *testing.T) {
	sentinel := errors.New("flush failed")
	writer := &publicationFaultWriter{header: http.Header{}, failure: sentinel}
	response := &publicResponse{ResponseWriter: writer, ctx: context.Background(), clock: time.Now}
	if err := http.NewResponseController(response).Flush(); !errors.Is(err, sentinel) || writer.flushes != 1 {
		t.Fatal("flush error lost", err)
	}
}

func TestCompletePublicResponseThroughReprintWriter(t *testing.T) {
	for _, cancelAfterWrite := range []bool{false, true} {
		s, err := delivery.New(delivery.MaxBudgetBits)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		writer := &publicationFaultWriter{header: http.Header{}}
		if cancelAfterWrite {
			writer.afterWrite = cancel
		}
		body := []byte(strings.Repeat("x", 40000))
		handler := s.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			protected := &reprintResponseWriter{ResponseWriter: w}
			public := &publicResponse{ResponseWriter: protected, ctx: ctx, clock: time.Now}
			_, _ = public.WriteResponse(206, body)
		}))
		request, _ := http.NewRequestWithContext(ctx, "GET", "http://example.test/", nil)
		request.RemoteAddr = "192.0.2.1:1234"
		var interrupted any
		func() {
			defer func() { interrupted = recover() }()
			handler.ServeHTTP(writer, request)
		}()
		if cancelAfterWrite {
			if interrupted != http.ErrAbortHandler || len(writer.sizes) != 1 {
				t.Fatal("cancelled public body continued", interrupted, writer.sizes)
			}
		} else if interrupted != nil || len(writer.sizes) < 2 {
			t.Fatal("public body not delivered", interrupted, writer.sizes)
		}
		if writer.header.Get("Cache-Control") != "private, no-cache" || !strings.Contains(strings.Join(writer.header.Values("Vary"), ","), "User-Agent") {
			t.Fatal("reprint boundary bypassed", writer.header)
		}
		for _, size := range writer.sizes {
			if size > delivery.Chunk {
				t.Fatal("unchecked public chunk", size)
			}
		}
		if q, n, a := s.Stats(); q != 0 || n != 0 || a != 0 {
			t.Fatal("cancelled response retained send slots", q, n, a)
		}
		cancel()
		s.Close()
	}
}

func TestCompletePublicResponseLeaseExpiresAfterChunk(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "complete", "確定本文")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	accepted, err := sendForm(form, url.Values{"bbs": {"complete"}, "subject": {"expiry"}, "MESSAGE": {"body"}, "oimo_request_id": {"complete-create-0001"}})
	if err != nil || !accepted.Accepted {
		t.Fatal(accepted, err)
	}
	snapshot, err := repo.Thread(t.Context(), board.ID, accepted.Key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	writer := &publicationFaultWriter{header: http.Header{}, afterWrite: func() { now = time.Unix(0, int64(snapshot.Expires)) }}
	s, err := delivery.New(delivery.MaxBudgetBits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var writeError error
	handler := s.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		public, err := publicWriter(&reprintResponseWriter{ResponseWriter: w}, r, snapshot, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		defer public.Close()
		_, writeError = public.WriteResponse(200, []byte(strings.Repeat("x", 40000)))
	}))
	request, _ := http.NewRequestWithContext(t.Context(), "GET", "http://example.test/", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	var interrupted any
	func() {
		defer func() { interrupted = recover() }()
		handler.ServeHTTP(writer, request)
	}()
	if !errors.Is(writeError, app.ErrPublicationGone) || interrupted != http.ErrAbortHandler || len(writer.sizes) != 1 {
		t.Fatal("expired completed body continued", writeError, interrupted, writer.sizes)
	}
	if q, n, a := s.Stats(); q != 0 || n != 0 || a != 0 {
		t.Fatal("expired completed body retained slots", q, n, a)
	}
}
