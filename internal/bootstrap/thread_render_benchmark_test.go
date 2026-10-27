// 同じ公開DATのHTML生成と共有取得を比較し、本文の一致を計測前に確認する。
package bootstrap

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"testing"

	"oimobbs/internal/compat"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstdencode"
)

func BenchmarkThreadHTMLRepresentation(b *testing.B) {
	raw := testutil.DATFixture("entropy")
	numbers := make([]int, 50)
	for i := range numbers {
		numbers[i] = i + 1
	}
	render := func() ([]byte, error) {
		rows, err := threadRows(raw, 1000, numbers)
		if err != nil {
			return nil, err
		}
		var body bytes.Buffer
		err = threadTemplate.Execute(&body, threadPage{Title: "title", Key: "123", Board: "probe", Count: 1000, Rows: rows, CanReply: true})
		return body.Bytes(), err
	}
	expected, err := render()
	if err != nil {
		b.Fatal(err)
	}
	for _, shared := range []bool{false, true} {
		b.Run(fmt.Sprint("shared=", shared), func(b *testing.B) {
			cache := compat.NewCompressionCache(1<<20, 2)
			get := render
			if shared {
				get = func() ([]byte, error) { return cache.Render(b.Context(), "same-public-version", render) }
			}
			got, err := get()
			if err != nil || !bytes.Equal(got, expected) {
				b.Fatal("different HTML", err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(expected)))
			b.ResetTimer()
			for b.Loop() {
				if _, err := get(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkThreadCompressionTarget は実テンプレートの最終50レスでgzip9と配信zstdを比較する。
// HTML生成・圧縮器初期化は計時外とし、改版ごとの圧縮・出力確保・総CPU時間を測る。
func BenchmarkThreadCompressionTarget(b *testing.B) {
	for _, kind := range []string{"text", "mixed", "entropy"} {
		raw := testutil.DATFixture(kind)
		numbers := make([]int, 50)
		for i := range numbers {
			numbers[i] = 951 + i
		}
		rows, err := threadRows(raw, 1000, numbers)
		if err != nil {
			b.Fatal(err)
		}
		var rendered bytes.Buffer
		if err := threadTemplate.Execute(&rendered, threadPage{Title: "title", Key: "123", Board: "probe", Count: 1000, Rows: rows, CanReply: true}); err != nil {
			b.Fatal(err)
		}
		body := rendered.Bytes()
		b.Run(kind, func(b *testing.B) {
			for _, coding := range []string{"zstd", "gzip9"} {
				b.Run(coding, func(b *testing.B) {
					var encoder zstdencode.Encoder
					writer, err := gzip.NewWriterLevel(io.Discard, gzip.BestCompression)
					if err != nil {
						b.Fatal(err)
					}
					encode := func() []byte {
						if coding == "zstd" {
							return encoder.Encode(body)
						}
						var output bytes.Buffer
						writer.Reset(&output)
						if _, err := writer.Write(body); err != nil {
							b.Fatal(err)
						}
						if err := writer.Close(); err != nil {
							b.Fatal(err)
						}
						return output.Bytes()
					}
					encoded := encode()
					if coding == "zstd" {
						decoded, err := testutil.DecodeZstd(encoded)
						if err != nil || !bytes.Equal(decoded, body) {
							b.Fatal("independent decode", err)
						}
					}
					cpuBefore, err := testutil.ProcessCPUTime()
					if err != nil {
						b.Fatal(err)
					}
					b.SetBytes(int64(len(body)))
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

// BenchmarkThreadHTMLWorkingSet は32MiB分の異なる公開版を巡回し、実HTMLの再生成費用を測る。
// 各キーは独立したスレッド版を模し、投稿による版更新やネットワークは含めない。
func BenchmarkThreadHTMLWorkingSet(b *testing.B) {
	raw := testutil.DATFixture("entropy")
	numbers := make([]int, 50)
	for i := range numbers {
		numbers[i] = i + 1
	}
	render := func() ([]byte, error) {
		rows, err := threadRows(raw, 1000, numbers)
		if err != nil {
			return nil, err
		}
		var body bytes.Buffer
		err = threadTemplate.Execute(&body, threadPage{Title: "title", Key: "123", Board: "probe", Count: 1000, Rows: rows, CanReply: true})
		return body.Bytes(), err
	}
	expected, err := render()
	if err != nil {
		b.Fatal(err)
	}
	keys := make([]string, (32<<20)/cap(expected)+1)
	if len(keys) > 1024 {
		b.Fatal("fixture exceeds cache entry bound", len(keys))
	}
	for i := range keys {
		keys[i] = fmt.Sprintf("thread-%d-public-version-1", i)
	}
	for _, limit := range []uint64{16 << 20, 128 << 20} {
		b.Run(fmt.Sprintf("cache=%dMiB", limit>>20), func(b *testing.B) {
			cache := compat.NewCompressionCache(limit, 4)
			for _, key := range keys {
				got, err := cache.Render(b.Context(), key, render)
				if err != nil || !bytes.Equal(got, expected) {
					b.Fatal("different HTML", err)
				}
			}
			before := cache.Status()
			b.ReportAllocs()
			b.ResetTimer()
			i := 0
			for b.Loop() {
				if _, err := cache.Render(b.Context(), keys[i%len(keys)], render); err != nil {
					b.Fatal(err)
				}
				i++
			}
			b.StopTimer()
			after := cache.Status()
			b.ReportMetric(float64(after.Builds-before.Builds)/float64(b.N), "builds/op")
			b.ReportMetric(float64(after.Used)/(1<<20), "retained-MiB")
		})
	}
}

// BenchmarkLiveThreadCompression は実テンプレートの最終50レスでCPUと転送byteの交換条件を測る。
func BenchmarkLiveThreadCompression(b *testing.B) {
	for _, kind := range []string{"mixed", "entropy", "repeated"} {
		b.Run(kind, func(b *testing.B) {
			raw := testutil.DATFixture(kind)
			numbers := make([]int, 50)
			for i := range numbers {
				numbers[i] = 951 + i
			}
			rows, err := threadRows(raw, 1000, numbers)
			if err != nil {
				b.Fatal(err)
			}
			var rendered bytes.Buffer
			if err := threadTemplate.Execute(&rendered, threadPage{Title: "title", Key: "123", Board: "probe", Count: 1000, Rows: rows, CanReply: true}); err != nil {
				b.Fatal(err)
			}
			body := rendered.Bytes()
			for _, live := range []bool{false, true} {
				b.Run(fmt.Sprint(live), func(b *testing.B) {
					c := compat.NewCompressionCache(0, 1)
					b.ReportAllocs()
					b.SetBytes(int64(len(body)))
					for b.Loop() {
						var encoded []byte
						var err error
						if live {
							encoded, err = c.CompressLive(b.Context(), "gzip", "version", body)
						} else {
							encoded, err = c.Compress(b.Context(), "gzip", "version", body)
						}
						if err != nil {
							b.Fatal(err)
						}
						b.ReportMetric(float64(len(encoded)), "compressed-bytes")
					}
				})
			}
		})
	}
}
