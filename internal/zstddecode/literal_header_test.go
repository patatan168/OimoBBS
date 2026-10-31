// 短いliteralヘッダーの境界と切り詰めを、公開形式の値で検査する。
package zstddecode

import (
	"bytes"
	"fmt"
	"testing"
)

// TestRawLiteralHeaderWidths は1/2/3byteのraw長とscratchの所有権を確認する。
func TestRawLiteralHeaderWidths(t *testing.T) {
	for _, size := range []int{0, 1, 31, 32, 255, 4095, 4096, blockSize} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			width := 3
			value := uint32(size)<<4 | 12
			if size < 32 {
				width = 1
				value = uint32(size) << 3
			} else if size < 4096 {
				width = 2
				value = uint32(size)<<4 | 4
			}
			data := make([]byte, width+size)
			for i := range width {
				data[i] = byte(value >> uint(8*i))
			}
			for i := range size {
				data[width+i] = byte(i)
			}
			scratch := bytes.Repeat([]byte{0x7e}, 19)
			before := bytes.Clone(scratch)
			out, used, err := decodeLiterals(data, &scratch)
			if err != nil || used != len(data) || !bytes.Equal(out, data[width:]) || !bytes.Equal(scratch, before) {
				t.Fatal("raw length or scratch changed", used, err)
			}
			if len(data) > width && size > 0 {
				if _, _, err = decodeLiterals(data[:len(data)-1], &scratch); err == nil {
					t.Fatal("truncated raw literal accepted")
				}
			}
		})
	}
}

// TestLiteralHeaderRejectsTruncation は表・stream形式を読める長さになる前の入力を拒否する。
func TestLiteralHeaderRejectsTruncation(t *testing.T) {
	for _, data := range [][]byte{nil, {4}, {12, 0}, {2, 0}, {6, 0}, {10, 0, 0}, {14, 0, 0, 0}, {1}, {3}, {2, 0, 0}, {6, 0, 0}, {10, 0, 0, 0}, {14, 0, 0, 0, 0}} {
		if _, err := readLiteralHeader(data); err == nil {
			t.Fatalf("malformed header accepted: %x", data)
		}
	}
}
