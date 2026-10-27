// HTTP共通の要求枠・送信枠の費用を、本文生成や永続化を含めず測定する。
package delivery

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

type commonBenchmarkWriter struct {
	header http.Header
	status int
	bytes  int
}

func (w *commonBenchmarkWriter) Header() http.Header    { return w.header }
func (w *commonBenchmarkWriter) WriteHeader(status int) { w.status = status }
func (w *commonBenchmarkWriter) Write(body []byte) (int, error) {
	w.bytes += len(body)
	return len(body), nil
}

// BenchmarkCommonHTTPResponse はsocketを除く共通ミドルウェアのCPU・割当を比較する。
func BenchmarkCommonHTTPResponse(b *testing.B) {
	for _, tc := range []struct {
		name     string
		size     int
		complete bool
	}{{"304", 0, false}, {"1KiB", 1 << 10, false}, {"64KiB", 64 << 10, false}, {"complete64KiB", 64 << 10, true}} {
		b.Run(tc.name, func(b *testing.B) {
			s, err := New(MaxBudgetBits)
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			gate, err := NewRequestGate(2048, 32)
			if err != nil {
				b.Fatal(err)
			}
			body := bytes.Repeat([]byte("x"), tc.size)
			handler := s.Wrap(gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				if tc.size == 0 {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				if tc.complete {
					_, err = w.(interface {
						WriteResponse(int, []byte) (int, error)
					}).WriteResponse(200, body)
				} else {
					_, err = w.Write(body)
				}
			})))
			request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil).WithContext(b.Context())
			request.RemoteAddr = "192.0.2.1:43210"
			writer := &commonBenchmarkWriter{header: make(http.Header)}
			b.ReportAllocs()
			for b.Loop() {
				writer.status, writer.bytes = 0, 0
				handler.ServeHTTP(writer, request)
				if err != nil || writer.bytes != tc.size || writer.status != 200 && writer.status != 304 {
					b.Fatal("incomplete response", writer.status, writer.bytes, err)
				}
			}
		})
	}
}
