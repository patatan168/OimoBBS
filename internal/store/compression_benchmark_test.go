// 保存用の実候補選択と復号を用い、圧縮サイズと作業確保量を測定する。
package store

import (
	"bytes"
	"oimobbs/internal/testutil"
	"testing"
)

func BenchmarkPackCompressionTarget(b *testing.B) {
	for _, kind := range []string{"text", "mixed", "entropy"} {
		raw := testutil.DATFixture(kind)
		b.Run(kind, func(b *testing.B) {
			chunk, err := EncodePackChunk(raw, 9)
			if err != nil {
				b.Fatal(err)
			}
			decoded, err := DecodePackChunk(chunk)
			if err != nil || !bytes.Equal(raw, decoded) {
				b.Fatal("roundtrip", err)
			}
			cpuBefore, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := EncodePackChunk(raw, 9); err != nil {
					b.Fatal(err)
				}
			}
			cpuAfter, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
			b.ReportMetric(float64(len(chunk.Stored)), "encoded-bytes")
		})
	}
}
