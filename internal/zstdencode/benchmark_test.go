// 合成DATで圧縮のCPU・確保量を測定する。復号は計測区間外で行う。
package zstdencode

import (
	"bytes"
	"compress/gzip"
	"io"
	"oimobbs/internal/testutil"
	"os"
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

// BenchmarkCompressionTarget は同じ入力でgzip最高圧縮と配信・固定候補zstdを比較する。
// gzipのwriter生成は計時外とし、各圧縮器が返す出力配列の確保は含める。
func BenchmarkCompressionTarget(b *testing.B) {
	for _, kind := range []string{"text", "mixed", "entropy", "html", "manual"} {
		raw := testutil.DATFixture(kind)
		if kind == "html" || kind == "manual" {
			path := "../webui/templates/common.html"
			if kind == "manual" {
				path = "../../docs/features/administration.md"
			}
			var err error
			raw, err = os.ReadFile(path)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.Run(kind, func(b *testing.B) {
			var encoder Encoder
			writer, err := gzip.NewWriterLevel(io.Discard, gzip.BestCompression)
			if err != nil {
				b.Fatal(err)
			}
			for _, codec := range []string{"zstd", "archive9", "gzip9"} {
				b.Run(codec, func(b *testing.B) {
					encode := func() []byte {
						switch codec {
						case "zstd":
							return encoder.Encode(raw)
						case "archive9":
							result, err := encoder.EncodeBestArchive(raw, []ArchiveOptions{{AccuracyLog: 8}, {AccuracyLog: 9}, {HashBytes: 7, AccuracyLog: 8}, {HashBytes: 4, AccuracyLog: 9}})
							if err != nil {
								b.Fatal(err)
							}
							return result
						default:
							var output bytes.Buffer
							writer.Reset(&output)
							if _, err := writer.Write(raw); err != nil {
								b.Fatal(err)
							}
							if err := writer.Close(); err != nil {
								b.Fatal(err)
							}
							return output.Bytes()
						}
					}
					encoded := encode()
					cpuBefore, err := testutil.ProcessCPUTime()
					if err != nil {
						b.Fatal(err)
					}
					b.SetBytes(int64(len(raw)))
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						encode()
					}
					cpuAfter, err := testutil.ProcessCPUTime()
					if err != nil {
						b.Fatal(err)
					}
					b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
					b.ReportMetric(float64(len(encoded)), "encoded-bytes")
				})
			}
		})
	}
}
