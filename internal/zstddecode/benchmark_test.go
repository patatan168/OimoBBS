// 固定した圧縮入力で復号時間・割当とCPU profileを比較する。
package zstddecode

import (
	"bytes"
	"math/rand"
	"testing"

	"oimobbs/internal/testutil"
	"oimobbs/internal/zstdencode"
)

func BenchmarkDecode(b *testing.B) {
	random := make([]byte, 512<<10)
	rand.New(rand.NewSource(71)).Read(random)
	samples := []struct {
		name string
		raw  []byte
	}{
		{"text", testutil.DATFixture("text")},
		{"mixed", testutil.DATFixture("mixed")},
		{"entropy", testutil.DATFixture("entropy")},
		{"raw", random},
		{"repeat", bytes.Repeat([]byte("abcde"), 100000)},
	}
	for _, sample := range samples {
		var encoder zstdencode.Encoder
		frame := encoder.Encode(sample.raw)
		b.Run(sample.name, func(b *testing.B) {
			cpuBefore, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(sample.raw)))
			b.ReportAllocs()
			for b.Loop() {
				out, err := Decode(frame, len(sample.raw))
				if err != nil || len(out) != len(sample.raw) {
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

// BenchmarkDecodeParallel は独立frameの同時展開で、コア数に対する総処理量を測る。
func BenchmarkDecodeParallel(b *testing.B) {
	for _, name := range []string{"text", "mixed", "entropy"} {
		raw := testutil.DATFixture(name)
		var encoder zstdencode.Encoder
		frame := encoder.Encode(raw)
		b.Run(name, func(b *testing.B) {
			cpuBefore, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					out, err := Decode(frame, len(raw))
					if err != nil || len(out) != len(raw) {
						b.Error("decode", err)
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
