// WAFの通常要求への追加費用を、同一の小さなHTTP応答で比較する。
package bootstrap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type wafBenchmarkWriter struct {
	header http.Header
	status int
}

func (w *wafBenchmarkWriter) Header() http.Header            { return w.header }
func (w *wafBenchmarkWriter) WriteHeader(status int)         { w.status = status }
func (w *wafBenchmarkWriter) Write(body []byte) (int, error) { return len(body), nil }

// BenchmarkWAFMiddleware は100000回以内の短いburstで計測する。
// ネットワーク・DBを除く追加費用であり、本番の処理能力を表すものではない。
func BenchmarkWAFMiddleware(b *testing.B) {
	for _, mode := range []string{"off", "inspection", "inspection_and_traffic"} {
		b.Run(mode, func(b *testing.B) {
			if b.N > 100000 {
				b.Skip("use -benchtime=100000x to stay within the configured burst")
			}
			repo := &Repository{}
			policy := repo.wafSettings()
			policy.Enabled = mode != "off"
			policy.Traffic.Enabled = mode == "inspection_and_traffic"
			policy.Traffic.ClientRate = 10000
			policy.Traffic.ClientBurst = 100000
			policy.Traffic.GlobalRate = 100000
			policy.Traffic.GlobalBurst = 200000
			policy.Traffic.ClientConcurrent = 128
			policy.Traffic.GlobalConcurrent = 2048
			repo.publishWAF(policy)
			requests := make([]*http.Request, 1024)
			for i := range requests {
				path := "/news/dat/1234567890.dat"
				if i%4 == 0 {
					path = "/news/subject.txt"
				}
				if i%4 == 1 {
					path = "/news/?page=2"
				}
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.RemoteAddr = fmt.Sprintf("192.0.%d.%d:43210", i/256, i%256)
				req.Header.Set("User-Agent", "Monazilla/1.00 OimoBrowser/1.0")
				req.Header.Set("Range", "bytes=1024-")
				req.Header.Set("If-None-Match", `"example-etag"`)
				requests[i] = req
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(304) })
			handler := repo.trafficHandler(repo.wafHandler(next), false)
			var failures atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				writer := &wafBenchmarkWriter{header: make(http.Header)}
				index := 0
				for pb.Next() {
					writer.status = 0
					handler.ServeHTTP(writer, requests[index%len(requests)])
					if writer.status != 304 {
						failures.Add(1)
					}
					index++
				}
			})
			b.StopTimer()
			if failures.Load() != 0 {
				b.Fatalf("%d requests throttled: use -benchtime=100000x or less", failures.Load())
			}
		})
	}
}
