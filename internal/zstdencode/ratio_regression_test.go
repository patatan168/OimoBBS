// 高圧縮化のサイズ目標と、保存frameのRLE境界を独立復号器で検証する。
package zstdencode

import (
	"bytes"
	"testing"

	"oimobbs/internal/testutil"
)

func TestTextCompressionRatioRegression(t *testing.T) {
	raw := testutil.DATFixture("text")
	frame := (&Encoder{}).Encode(raw)
	if len(frame) > 12160 {
		t.Fatalf("text DAT compression regression: %d bytes", len(frame))
	}
	decoded, err := testutil.DecodeZstd(frame)
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatal("independent decode", err)
	}
}

func TestArchiveRLEPreservesRepeatHistory(t *testing.T) {
	prefix := testutil.DATFixture("mixed")[:blockLimit]
	raw := append(bytes.Clone(prefix), bytes.Repeat([]byte{0xee}, blockLimit)...)
	raw = append(raw, prefix...)
	for _, option := range []ArchiveOptions{{AccuracyLog: 7}, {AccuracyLog: 8}, {AccuracyLog: 9, HashBytes: 4, OptimizeEntropy: true}} {
		frame, err := (&Encoder{}).EncodeArchive(raw, option)
		if err != nil {
			t.Fatal(err)
		}
		if modes := checkRLEFrame(t, raw, frame); !bytes.Equal(modes, []byte{2, 1, 2}) {
			t.Fatal("archive block modes", option, modes)
		}
	}
}
