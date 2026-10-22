// 送信予約の待機中に失効した証拠データを、下位writerへ渡さないことを検査する。
package bootstrap

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// delayedEvidenceWriter は帯域待ち完了に相当する時点で失効させる。実時間の待機は使わない。
type delayedEvidenceWriter struct {
	*httptest.ResponseRecorder
	expired        bool
	headersWritten int
}

func (w *delayedEvidenceWriter) WriteHeader(status int) {
	w.headersWritten++
	w.ResponseRecorder.WriteHeader(status)
}

func (w *delayedEvidenceWriter) WriteChecked(raw []byte, check func() error) (int, error) {
	w.expired = true
	if err := check(); err != nil {
		return 0, err
	}
	return w.ResponseRecorder.Write(raw)
}

func (w *delayedEvidenceWriter) WriteHeaderChecked(status int, check func() error) error {
	w.expired = true
	if err := check(); err != nil {
		return err
	}
	w.WriteHeader(status)
	return nil
}

func TestEvidenceSendChecksAfterReservation(t *testing.T) {
	for _, mounted := range []bool{false, true} {
		for _, headers := range []bool{false, true} {
			w := &delayedEvidenceWriter{ResponseRecorder: httptest.NewRecorder()}
			var destination http.ResponseWriter = w
			if mounted {
				destination = &adminMountResponse{ResponseWriter: w, base: "/_manage-0123456789abcdef"}
			}
			guard := &adminCheckedWriter{ResponseWriter: destination, check: func() error {
				if w.expired {
					return errors.New("evidence permission expired during reservation")
				}
				return nil
			}}
			func() {
				defer func() {
					if got := recover(); got != http.ErrAbortHandler {
						t.Errorf("expired send not aborted: headers=%t panic=%v", headers, got)
					}
				}()
				if headers {
					guard.WriteHeader(http.StatusOK)
				} else {
					_, _ = guard.Write([]byte("PRIVATE_EVIDENCE"))
				}
			}()
			if !w.expired || w.headersWritten != 0 || w.Body.Len() != 0 || w.Flushed {
				t.Fatal("expired evidence transmitted")
			}
		}
	}
}
