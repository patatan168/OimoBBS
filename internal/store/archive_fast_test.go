// 廃止した保存level 9の追加探索を実行せず、既存level 9も安全に扱うことを検査する。
package store

import (
	"bytes"
	"testing"

	"oimobbs/internal/testutil"
	"oimobbs/internal/zstdencode"
)

func TestLegacyArchiveLevelUsesSinglePass(t *testing.T) {
	var e zstdencode.Encoder
	for _, raw := range [][]byte{[]byte("short legacy chunk"), testutil.DATFixture("text"), testutil.DATFixture("entropy"), testutil.EntropyDATFixture("base64", 512<<10, 97)} {
		chunk, err := EncodePackChunk(raw, 9)
		if err != nil || !bytes.Equal(chunk.Stored, e.Encode(raw)) {
			t.Fatal("legacy level repeated compression", err)
		}
		out, err := DecodePackChunk(chunk)
		if err != nil || !bytes.Equal(out, raw) {
			t.Fatal("legacy level content changed", err)
		}
	}
}
