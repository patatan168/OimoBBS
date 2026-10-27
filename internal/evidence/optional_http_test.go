// 実HTTP要求の受理裁定・request対応・実write結果と秘密非収集を独立に検査する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/domain"
	"os"
	"strings"
	"testing"
)

func TestOptionalHTTPDurablePrivacyAndRequestLink(t *testing.T) {
	observer := testObserver(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := OpenOptionalStore(root, observer.site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	q, e := NewOptionalQueue(s.Write)
	if e != nil {
		t.Fatal(e)
	}
	board, operation := domain.NewID(), domain.NewID()
	observations := make(chan HTTPObservation, 1)
	handler := observer.WrapOptional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			capture, e := observer.Begin(r, board, "bbs_post", "example.test")
			if e != nil {
				t.Error(e)
				w.WriteHeader(500)
				return
			}
			if _, e = io.Copy(io.Discard, r.Body); e != nil {
				t.Error(e)
				return
			}
			observation, e := capture.Finish()
			if e != nil {
				t.Error(e)
				return
			}
			observations <- observation
			if e = AnnotateOptionalPosting(r.Context(), board, &operation, "accepted"); e != nil {
				t.Error(e)
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte("ok"))
			return
		}
		r.Header.Set("User-Agent", "changed in handler")
		w.WriteHeader(204)
	}), q, func(r *http.Request) string {
		if r.Method == "POST" {
			return "legacy_post"
		}
		return "home"
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	request, _ := http.NewRequest("POST", server.URL+"/test/bbs.cgi?URL_QUERY_SECRET=x", strings.NewReader("MESSAGE=REJECTED_BODY_SECRET&password=AUTH_SECRET"))
	request.Header.Set("Cookie", "oimo_anon=COOKIE_SECRET")
	request.Header.Set("Authorization", "AUTH_SECRET")
	request.Header.Set("User-Agent", "observed-ua")
	response, e := server.Client().Do(request)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	request, _ = http.NewRequest("GET", server.URL+"/?URL_QUERY_SECRET=x", nil)
	request.Header.Set("User-Agent", "original-reader-ua")
	response, e = server.Client().Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	server.Close()
	if e = q.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if q.Status().Saved != 3 {
		t.Fatal(q.Status())
	}
	observation := <-observations
	posted, read := 0, 0
	for _, j := range s.journals {
		for _, entry := range j.entries {
			var p OptionalPayload
			if json.Unmarshal(entry.Payload, &p) != nil {
				t.Fatal("payload")
			}
			raw := string(entry.Payload)
			for _, secret := range []string{"URL_QUERY_SECRET", "REJECTED_BODY_SECRET", "COOKIE_SECRET", "AUTH_SECRET"} {
				if strings.Contains(raw, secret) {
					t.Fatal("secret persisted", secret)
				}
			}
			if p.Record.Kind == "access" {
				read++
				if p.Record.UserAgent.Display != "original-reader-ua" || p.Record.Status != 204 {
					t.Fatal(p.Record)
				}
				continue
			}
			posted++
			if p.Record.Request != observation.RequestID || p.Record.Received != observation.Received || p.Record.Connection != observation.ConnectionID || p.Record.Operation == nil || *p.Record.Operation != operation || p.Record.Outcome != "accepted" || p.Record.Status != 201 || p.Record.Bytes != 2 || p.Record.FinishStage != "handler_return" {
				t.Fatal(p.Record, observation)
			}
		}
	}
	if posted != 2 || read != 1 {
		t.Fatal(posted, read)
	}
}

type failingOptionalWriter struct{ header http.Header }

func (w *failingOptionalWriter) Header() http.Header { return w.header }
func (w *failingOptionalWriter) WriteHeader(int)     {}
func (w *failingOptionalWriter) Write([]byte) (int, error) {
	return 2, errors.New("PRIVATE_WRITE_ERROR")
}
func (w *failingOptionalWriter) FlushError() error { return errors.New("PRIVATE_FLUSH_ERROR") }

func TestOptionalHTTPWriteFailureAndMissingObservation(t *testing.T) {
	observer, request := observationRequest(t, http.NoBody)
	rows := make(chan OptionalRecord, 2)
	q, e := NewOptionalQueue(func(_ context.Context, record OptionalRecord) error { rows <- record; return nil })
	if e != nil {
		t.Fatal(e)
	}
	handler := observer.WrapOptional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		_, _ = w.Write([]byte("abcdef"))
		_ = http.NewResponseController(w).Flush()
	}), q, nil)
	handler.ServeHTTP(&failingOptionalWriter{header: http.Header{}}, request)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.test/", nil))
	if e = q.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	record := <-rows
	if !record.WriteFailed || record.Bytes != 2 || record.Status != 202 || record.Outcome != "interrupted" || q.Status().Saved != 1 || q.Status().DroppedInvalid != 1 {
		t.Fatal(record, q.Status())
	}
}
