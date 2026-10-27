// 精度選択の圧縮サイズ、独立復号、候補比較のCPU数によらない決定性を検証する。
package zstdencode

import (
	"bytes"
	"math/rand/v2"
	"oimobbs/internal/testutil"
	"runtime"
	"testing"
)

// TestEntropyChoiceNoLargerThanFixed は単一blockで固定精度7〜9より大きくならないことを確認する。
func TestEntropyChoiceNoLargerThanFixed(t *testing.T) {
	rng := rand.New(rand.NewPCG(171, 39))
	samples := [][]byte{nil, []byte("small"), testutil.DATFixture("text")[:64000], testutil.DATFixture("mixed")[:64000]}
	for _, alphabet := range []int{2, 31, 32, 33, 53, 256} {
		raw := make([]byte, 48000)
		for i := range raw {
			raw[i] = byte(rng.IntN(alphabet))
		}
		samples = append(samples, raw)
	}
	var optimized, fixed Encoder
	for _, raw := range samples {
		frame := optimized.Encode(raw)
		decoded, err := testutil.DecodeZstd(frame)
		if err != nil || !bytes.Equal(raw, decoded) {
			t.Fatal("independent decoder", len(raw), err)
		}
		for log := uint(7); log <= 9; log++ {
			candidate, err := fixed.EncodeArchive(raw, ArchiveOptions{AccuracyLog: log})
			if err != nil {
				t.Fatal(err)
			}
			if len(frame) > len(candidate) {
				t.Fatalf("size=%d log=%d optimized=%d fixed=%d", len(raw), log, len(frame), len(candidate))
			}
		}
	}
}

func TestArchiveCandidateParallelDeterminism(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	options := []ArchiveOptions{{AccuracyLog: 8}, {AccuracyLog: 9, OptimizeEntropy: true}, {HashBytes: 4, AccuracyLog: 9, OptimizeEntropy: true}}
	var encoder Encoder
	for _, kind := range []string{"text", "mixed", "entropy"} {
		raw := testutil.DATFixture(kind)
		runtime.GOMAXPROCS(1)
		serial, err := encoder.EncodeBestArchive(raw, options)
		if err != nil {
			t.Fatal(err)
		}
		for _, cpus := range []int{2, 4} {
			runtime.GOMAXPROCS(cpus)
			parallel, err := encoder.EncodeBestArchive(raw, options)
			if err != nil || !bytes.Equal(parallel, serial) {
				t.Fatal(kind, cpus, "parallel output changed", err)
			}
		}
		if !bytes.Equal(encoder.Encode(raw), (&Encoder{}).Encode(raw)) {
			t.Fatal("archive option leaked into HTTP compression")
		}
	}
}
