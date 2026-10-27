// 出力末尾をliteral作業領域に使っても、未消費literalと確定済みprefixを壊さないことを検証する。
package zstddecode

import (
	"bytes"
	"testing"

	"oimobbs/internal/testutil"
	"oimobbs/internal/zstdencode"
)

func TestBlockLiteralsUseOutputTail(t *testing.T) {
	var encoder zstdencode.Encoder
	frame := encoder.Encode(testutil.DATFixture("entropy"))
	n := (int(frame[9]) | int(frame[10])<<8 | int(frame[11])<<16) >> 3
	block := frame[12 : 12+n]
	var scratch []byte
	want, used, err := decodeLiterals(block, &scratch)
	if err != nil || len(want) == 0 || block[0]&15 != 14 {
		t.Fatal("fixture requires compressed literals", err)
	}
	for _, gap := range []int{0, 1, 1024, blockSize} {
		prefix := []byte("already decoded bytes")
		size := len(prefix) + len(want) + gap
		backing := bytes.Repeat([]byte{0xaa}, size+1)
		copy(backing, prefix)
		out := backing[:len(prefix):size]
		got, at, err := decodeBlockLiterals(block, out, size)
		if err != nil || at != used || !bytes.Equal(got, want) || &got[0] != &backing[size-len(want)] {
			t.Fatal("literal tail mismatch", gap, err)
		}
		if !bytes.Equal(backing[:len(prefix)], prefix) || backing[size] != 0xaa {
			t.Fatal("literal decode overwrote prefix or guard")
		}
		// sequenceなしのblockでは、末尾のliteralを重複copyして確定する。
		literalOnly := append(bytes.Clone(block[:used]), 0)
		result, err := decodeBlock(literalOnly, out, size, &[3]int{1, 4, 8})
		if err != nil || !bytes.Equal(result, append(bytes.Clone(prefix), want...)) || backing[size] != 0xaa {
			t.Fatal("literal-only overlap mismatch", gap, err)
		}
	}
	out := make([]byte, 7, len(want)+6)
	if got, _, err := decodeBlockLiterals(block, out, cap(out)); err == nil || got != nil {
		t.Fatal("literals exceed remaining output")
	}
	// LL=0・OF=0・ML=0のRLE列は、履歴offset=4から3byteを出してからliteralを残す。
	withMatch := append(bytes.Clone(block[:used]), 1, 0x54, 0, 0, 0, 1)
	prefix := []byte("history bytes")
	for extra := 0; extra <= 3; extra++ {
		size := len(prefix) + len(want) + extra
		backing := bytes.Repeat([]byte{0xaa}, size+1)
		copy(backing, prefix)
		got, err := decodeBlock(withMatch, backing[:len(prefix):size], size, &[3]int{1, 4, 8})
		if extra < 3 {
			if err == nil || got != nil || !bytes.Equal(backing[size-len(want):size], want) {
				t.Fatal("match overwrote unread literals", extra, err)
			}
		} else {
			expected := append(bytes.Clone(prefix), prefix[len(prefix)-4:len(prefix)-1]...)
			expected = append(expected, want...)
			if err != nil || !bytes.Equal(got, expected) {
				t.Fatal("valid match rejected or changed literals", err)
			}
		}
		if !bytes.Equal(backing[:len(prefix)], prefix) || backing[size] != 0xaa {
			t.Fatal("match overwrote prefix or guard", extra)
		}
	}
}
