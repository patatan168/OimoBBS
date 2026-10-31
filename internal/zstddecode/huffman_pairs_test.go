// 2文字prefix表を、独立した1文字ずつのbit抽出と破損入力で照合する。
package zstddecode

import (
	"bytes"
	"testing"
)

func FuzzHuffmanPairsReference(f *testing.F) {
	f.Add([]byte{17, 29, 49, 255, 1}, uint8(6), uint16(32))
	f.Add([]byte{255, 255, 1}, uint8(11), uint16(4096))
	f.Add(append(bytes.Repeat([]byte{0x55}, 1024), 1), uint8(0), uint16(8192))
	f.Fuzz(func(t *testing.T, raw []byte, level uint8, count uint16) {
		if len(raw) > 4096 {
			t.Skip()
		}
		depth := int(level%11) + 1
		table := make([]huffmanCell, 1<<uint(depth))
		for symbol := 0; symbol <= depth; symbol++ {
			width := min(symbol+1, depth)
			code := (1 << uint(width)) - 2
			if symbol == depth {
				code++
			}
			for prefix := code << uint(depth-width); prefix < (code+1)<<uint(depth-width); prefix++ {
				table[prefix] = huffmanCell{byte(symbol), uint8(width)}
			}
		}
		data := [4][]byte{raw, raw, raw, raw}
		n := int(count % 8193)
		compareHuffmanFour(t, data, [4]int{n, n, n, n}, table, depth)
	})
}
