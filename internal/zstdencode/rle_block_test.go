// HTTPの一様なblock、非一様な周期、RLEを挟む履歴参照を独立復号器で照合する。
package zstdencode

import (
	"bytes"
	"fmt"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstddecode"
	"testing"
)

// TestHTTPRLEBlocks は展開長をblock headerへ記録し、payloadを1byteにすることを検査する。
func TestHTTPRLEBlocks(t *testing.T) {
	for _, size := range []int{2, 8, 9, 16, 17, 31, 32, 255, 256, 511, 512, 32768, blockLimit, blockLimit + 1, 2*blockLimit + 7} {
		for _, value := range []byte{0, 'x', 255} {
			t.Run(fmt.Sprintf("%d/%d", size, value), func(t *testing.T) {
				raw := bytes.Repeat([]byte{value}, size)
				frame := (&Encoder{}).Encode(raw)
				kinds := checkRLEFrame(t, raw, frame)
				for i, kind := range kinds {
					length := min(blockLimit, size-i*blockLimit)
					if length >= 17 && kind != 1 {
						t.Fatal("uniform block was not RLE", i, kind)
					}
				}
			})
		}
	}
}

// TestRLEBlockDoesNotChangeRepeats は圧縮・RLE・圧縮の境界でも参照履歴を維持する。
func TestRLEBlockDoesNotChangeRepeats(t *testing.T) {
	prefix := testutil.DATFixture("mixed")[:blockLimit]
	raw := append(bytes.Clone(prefix), bytes.Repeat([]byte{0xee}, blockLimit)...)
	raw = append(raw, prefix...)
	frame := (&Encoder{}).Encode(raw)
	kinds := checkRLEFrame(t, raw, frame)
	if !bytes.Equal(kinds, []byte{2, 1, 2}) {
		t.Fatal("unexpected block modes", kinds)
	}
}

// TestRLERejectsPeriodicAndTrailingLiterals は単一参照でも一様でなければRLEを選ばないことを確認する。
func TestRLERejectsPeriodicAndTrailingLiterals(t *testing.T) {
	samples := [][]byte{
		bytes.Repeat([]byte("abcd"), 70000),
		append(bytes.Repeat([]byte{'x'}, 299), 'y'),
		append(bytes.Repeat([]byte{'x'}, blockLimit-1), 'y'),
	}
	for _, raw := range samples {
		frame := (&Encoder{}).Encode(raw)
		for _, kind := range checkRLEFrame(t, raw, frame) {
			if kind == 1 {
				t.Fatal("non-uniform block treated as RLE")
			}
		}
	}
}

// checkRLEFrame は本文一致と厳密な末尾・出力上限を確認し、wire上のblock種別を返す。
func checkRLEFrame(t *testing.T, raw, frame []byte) []byte {
	t.Helper()
	independent, err := testutil.DecodeZstd(frame)
	if err != nil || !bytes.Equal(independent, raw) {
		t.Fatal("independent decode", err)
	}
	own, err := zstddecode.Decode(frame, len(raw))
	if err != nil || !bytes.Equal(own, raw) {
		t.Fatal("product decode", err)
	}
	for _, bad := range [][]byte{frame[:len(frame)-1], append(bytes.Clone(frame), 0)} {
		if partial, err := zstddecode.Decode(bad, len(raw)); err == nil || partial != nil {
			t.Fatal("invalid ending accepted")
		}
	}
	if _, err := zstddecode.Decode(frame, len(raw)-1); err == nil {
		t.Fatal("wrong length accepted")
	}
	var kinds []byte
	rawAt := 0
	for at := len(frameHeader(nil, uint64(len(raw)))); at < len(frame); {
		header := int(frame[at]) | int(frame[at+1])<<8 | int(frame[at+2])<<16
		at += 3
		size, kind := header>>3, byte(header>>1&3)
		kinds = append(kinds, kind)
		stored := size
		if kind == 1 {
			stored = 1
			if !bytes.Equal(raw[rawAt:rawAt+size], bytes.Repeat(frame[at:at+1], size)) {
				t.Fatal("RLE content differs")
			}
		}
		at += stored
		rawAt += min(blockLimit, len(raw)-rawAt)
	}
	return kinds
}
