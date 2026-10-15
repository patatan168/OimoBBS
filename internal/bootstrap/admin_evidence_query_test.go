// 案件照会の送信区切りと失効後の中断を通信待ちなしで検査する。
package bootstrap

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvidenceQueryWriterRevocation(t *testing.T) {
	recorder := httptest.NewRecorder()
	checks := 0
	w := &evidenceQueryWriter{ResponseWriter: recorder, check: func() error {
		checks++
		if checks == 2 {
			return errors.New("revoked")
		}
		return nil
	}}
	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Errorf("revocation did not abort HTTP: %v", r)
		}
		if recorder.Body.Len() != 32<<10 || checks != 2 {
			t.Errorf("bytes sent after revocation: %d %d", recorder.Body.Len(), checks)
		}
	}()
	w.Write(make([]byte, 64<<10))
}

type evidenceShortWriter struct{ http.ResponseWriter }

func (w evidenceShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestEvidenceQueryWriterShortWrite(t *testing.T) {
	w := &evidenceQueryWriter{ResponseWriter: evidenceShortWriter{httptest.NewRecorder()}, check: func() error { return nil }}
	n, e := w.Write(make([]byte, 10))
	if n != 9 || !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(n, e)
	}
}
