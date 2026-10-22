// 合成DATで圧縮のCPU・確保量を測定する。復号は計測区間外で行う。
package zstdencode

import (
	"bytes"
	"oimobbs/internal/testutil"
	"testing"
)

func BenchmarkEncode(b *testing.B) {
	for _, kind := range []string{"entropy", "text", "mixed"} {
		b.Run(kind, func(b *testing.B) {
			raw := testutil.DATFixture(kind)
			e := &Encoder{}
			encoded := e.Encode(raw)
			decoded, err := testutil.DecodeZstd(encoded)
			if err != nil || !bytes.Equal(raw, decoded) {
				b.Fatal("roundtrip", err)
			}
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				e.Encode(raw)
			}
			b.ReportMetric(float64(len(encoded)), "encoded-bytes")
		})
	}
}
