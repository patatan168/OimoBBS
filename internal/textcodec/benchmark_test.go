// 文字コード変換の単独待ち時間・同時要求の処理量・全thread CPU・割当を測る。
package textcodec_test

import (
	"strconv"
	"strings"
	"testing"

	"oimobbs/internal/testutil"
	"oimobbs/internal/textcodec"
)

// BenchmarkTextCodecThreshold は補助workerを無効化した同じ実装との比較にも使う。
func BenchmarkTextCodecThreshold(b *testing.B) {
	for _, size := range []int{64 << 10, 128 << 10, 256 << 10, 1 << 20} {
		pattern := "日本語の文字コード変換と並列処理ABC123\n"
		sample := conversionFixture{text: strings.Repeat(pattern, (size+len(pattern)-1)/len(pattern))}
		sample.encoded, _ = textcodec.Encode(sample.text, true)
		sample.decoded, _ = textcodec.Decode(sample.encoded)
		for _, mode := range []string{"encode", "decode"} {
			b.Run(mode+"/"+strconv.Itoa(size>>10)+"KiB", func(b *testing.B) {
				operation, inputBytes := conversionOperation(sample, mode)
				cpuBefore, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(inputBytes))
				b.ReportAllocs()
				for b.Loop() {
					if err := operation(); err != nil {
						b.Fatal(err)
					}
				}
				cpuAfter, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
			})
		}
	}
}

type conversionFixture struct {
	name    string
	text    string
	encoded []byte
	decoded string
}

func conversionFixtures(b *testing.B) []conversionFixture {
	b.Helper()
	fixtures := []conversionFixture{
		{name: "ascii", text: strings.Repeat("ASCII text 0123456789 <> &amp; \n", 16384)},
		{name: "japanese", text: strings.Repeat("日本語の文字コード変換と並列処理を確認します。\n", 8192)},
		{name: "mixed", text: strings.Repeat("name<>sage<>ID:1234<>日本語の本文とABC123、ｱｲｳ、URL https://example.invalid/<>\n", 4096)},
		{name: "references", text: strings.Repeat("返信 😀 🥺 𠮷 さんの本文です。ABC123\n", 8192)},
		{name: "halfwidth", text: strings.Repeat("ｱｲｳｴｵｶｷｸｹｺ", 16384)},
		{name: "lead_run", text: strings.Repeat("日", 131072)},
		{name: "small", text: "名前<>sage<>date ID:1234<>短い本文とABC123<>題名\n"},
	}
	for i := range fixtures {
		var err error
		fixtures[i].encoded, err = textcodec.Encode(fixtures[i].text, true)
		if err != nil {
			b.Fatal(err)
		}
		fixtures[i].decoded, err = textcodec.Decode(fixtures[i].encoded)
		if err != nil {
			b.Fatal(err)
		}
	}
	return fixtures
}

func BenchmarkTextCodec(b *testing.B) {
	for _, sample := range conversionFixtures(b) {
		for _, mode := range []string{"encode", "decode"} {
			b.Run(mode+"/"+sample.name, func(b *testing.B) {
				operation, size := conversionOperation(sample, mode)
				cpuBefore, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if err := operation(); err != nil {
						b.Fatal(err)
					}
				}
				cpuAfter, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
			})
		}
	}
}

func BenchmarkTextCodecConcurrent(b *testing.B) {
	for _, sample := range conversionFixtures(b) {
		for _, mode := range []string{"encode", "decode"} {
			b.Run(mode+"/"+sample.name, func(b *testing.B) {
				operation, size := conversionOperation(sample, mode)
				cpuBefore, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if err := operation(); err != nil {
							b.Error(err)
							return
						}
					}
				})
				cpuAfter, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
			})
		}
	}
}

// conversionOperation は同じ入力・成功長の条件を、単独と同時要求の両測定で共有する。
func conversionOperation(sample conversionFixture, mode string) (func() error, int) {
	if mode == "encode" {
		return func() error {
			out, err := textcodec.Encode(sample.text, true)
			if err == nil && len(out) != len(sample.encoded) {
				return errConversionSize
			}
			return err
		}, len(sample.text)
	}
	return func() error {
		out, err := textcodec.Decode(sample.encoded)
		if err == nil && len(out) != len(sample.decoded) {
			return errConversionSize
		}
		return err
	}, len(sample.encoded)
}

type conversionSizeError struct{}

func (conversionSizeError) Error() string { return "conversion size mismatch" }

var errConversionSize error = conversionSizeError{}
