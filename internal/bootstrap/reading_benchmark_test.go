// 閲覧応答の生成済みHTML再利用と本文なし再検証のCPU費用を測る。
package bootstrap

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"testing"

	"oimobbs/internal/compat"
)

func BenchmarkReadingFeedHTTP(b *testing.B) {
	for _, metadata := range []bool{false, true} {
		for _, size := range []int{32 << 10, 256 << 10} {
			body := bytes.Repeat([]byte("x"), size)
			for _, conditional := range []bool{false, true} {
				name := "full"
				if conditional {
					name = "304"
				}
				b.Run(fmt.Sprintf("metadata=%t/%s/%dKiB", metadata, name, size>>10), func(b *testing.B) {
					repo := &Repository{feedCompression: compat.NewCompressionCache(1<<20, 2)}
					r := httptest.NewRequest("GET", "/test/read.cgi/probe/123/", nil)
					w := httptest.NewRecorder()
					repo.writeFeed(w, r, "text/html; charset=UTF-8", body, nil)
					if conditional {
						r.Header.Set("If-None-Match", w.Header().Get("ETag"))
					}
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						w := httptest.NewRecorder()
						if metadata {
							cached, err := repo.feedCompression.RenderFeed(r.Context(), "public-version", func() ([]byte, error) { return body, nil })
							repo.writeRenderedFeed(w, r, "text/html; charset=UTF-8", cached, err)
						} else {
							cached, err := repo.feedCompression.Render(r.Context(), "public-version", func() ([]byte, error) { return body, nil })
							repo.writeFeed(w, r, "text/html; charset=UTF-8", cached, err)
						}
					}
				})
			}
		}
	}
}
