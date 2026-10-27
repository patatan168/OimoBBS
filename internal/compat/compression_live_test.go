// 更新の多いHTML向け圧縮を、本文一致・通常表現との分離・処理量で検証する。
package compat

import (
	"bytes"
	"context"
	"fmt"
	"testing"
)

func liveBody() []byte {
	var b bytes.Buffer
	b.WriteString("<!DOCTYPE html><html><head><title>試験</title></head><body>")
	for i := range 50 {
		fmt.Fprintf(&b, "<article><h2>名前 %d</h2><p>日本語の投稿本文。返信を表示しています。%d</p></article>", i, i)
	}
	b.WriteString("</body></html>")
	return b.Bytes()
}

func TestCompressionLiveProfiles(t *testing.T) {
	c := NewCompressionCache(1<<20, 1)
	raw := liveBody()
	for _, coding := range []string{"gzip", "zstd"} {
		a, err := c.CompressLive(t.Context(), coding, "version", raw)
		if err != nil || !bytes.Equal(decodeCoding(t, coding, a), raw) {
			t.Fatal("live content", err)
		}
		b, err := c.Compress(t.Context(), coding, "version", raw)
		if err != nil || !bytes.Equal(decodeCoding(t, coding, b), raw) {
			t.Fatal("regular content", err)
		}
		again, err := c.CompressLive(t.Context(), coding, "version", raw)
		if err != nil || !bytes.Equal(a, again) {
			t.Fatal("non deterministic", err)
		}
		if coding == "gzip" && GzipLiveETagSuffix == GzipETagSuffix {
			t.Fatal("strong tag reused across profiles")
		}
	}
	if c.Status().Builds != 3 {
		t.Fatal("profiles not isolated", c.Status())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.CompressLive(ctx, "gzip", "other", raw); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func BenchmarkCompressionLive(b *testing.B) {
	raw := liveBody()
	for _, live := range []bool{false, true} {
		b.Run(fmt.Sprint(live), func(b *testing.B) {
			c := NewCompressionCache(0, 1)
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for b.Loop() {
				var encoded []byte
				var err error
				if live {
					encoded, err = c.CompressLive(b.Context(), "gzip", "version", raw)
				} else {
					encoded, err = c.Compress(b.Context(), "gzip", "version", raw)
				}
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(len(encoded)), "compressed-bytes")
			}
		})
	}
}
