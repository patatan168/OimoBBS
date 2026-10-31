// 大きい高エントロピーDATの保存サイズと独立復号を検査する。
package zstdencode

import (
	"bytes"
	"math/rand/v2"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstddecode"
	"testing"
)

func TestLargeEntropyArchiveRatio(t *testing.T) {
	raw := testutil.DATFixture("entropy")
	options := []ArchiveOptions{{AccuracyLog: 9, OptimizeEntropy: true}, {HashBytes: 7, AccuracyLog: 9, OptimizeEntropy: true}, {HashBytes: 4, AccuracyLog: 9, OptimizeEntropy: true}}
	frame, err := (&Encoder{}).EncodeBestArchive(raw, options)
	if err != nil {
		t.Fatal(err)
	}
	// 比較元176,639byteに対し、少なくとも約0.05%の削減を維持する。
	if len(frame) > 176550 {
		t.Fatal("large entropy DAT did not shrink", len(frame))
	}
	for _, decode := range []func([]byte, int) ([]byte, error){zstddecode.Decode, func(frame []byte, _ int) ([]byte, error) { return testutil.DecodeZstd(frame) }} {
		decoded, err := decode(frame, len(raw))
		if err != nil || !bytes.Equal(decoded, raw) {
			t.Fatal("roundtrip", err)
		}
	}
}

// TestEntropyLiteralClassification は同じ分布でも未構造の乱数・通常文章・広い文字種を対象外にする。
func TestEntropyLiteralClassification(t *testing.T) {
	rng := rand.New(rand.NewPCG(9109, 31))
	noise := make([]byte, 128<<10)
	for i := range noise {
		noise[i] = "0123456789abcdef"[rng.IntN(16)]
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want bool
	}{
		{"original", testutil.DATFixture("entropy"), true},
		{"hex DAT", testutil.EntropyDATFixture("hex", 128<<10, 7), true},
		{"base64 DAT", testutil.EntropyDATFixture("base64", 128<<10, 97), false},
		{"text", testutil.DATFixture("text"), false},
		{"unstructured hex", noise, false},
		{"uniform", bytes.Repeat([]byte{0}, 128<<10), false},
	} {
		_, _, got := literalPrices(tc.raw[:min(len(tc.raw), 128<<10)])
		if got != tc.want {
			t.Fatal("classification", tc.name, got, tc.want)
		}
	}
}
