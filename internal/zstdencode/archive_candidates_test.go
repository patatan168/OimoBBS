// 候補間の配列再利用で既存の最小圧縮結果と返却配列の所有権が変わらないことを検査する。
package zstdencode

import (
	"bytes"
	"oimobbs/internal/testutil"
	"testing"
)

func TestArchiveCandidatesPreserveMinimumAndOwnership(t *testing.T) {
	options := []ArchiveOptions{{AccuracyLog: 8}, {AccuracyLog: 9}, {HashBytes: 7, AccuracyLog: 8}, {HashBytes: 4, AccuracyLog: 9}}
	var encoder Encoder
	for _, kind := range []string{"text", "mixed", "entropy"} {
		raw := testutil.DATFixture(kind)
		var want []byte
		for _, option := range options {
			var reference Encoder
			candidate, err := reference.EncodeArchive(raw, option)
			if err != nil {
				t.Fatal(err)
			}
			if want == nil || len(candidate) < len(want) {
				want = candidate
			}
		}
		got, err := encoder.EncodeBestArchive(raw, options)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal(kind, "minimum output changed", err)
		}
		_ = encoder.Encode([]byte("another input"))
		if !bytes.Equal(got, want) {
			t.Fatal("returned array changed on reuse")
		}
	}
}
