// ASCIIの連続部分を8byteずつ探し、1文字ずつの変換を一括copyへまとめる。
package textcodec

import "encoding/binary"

func asciiPrefixBytes(b []byte) int {
	i := 0
	for len(b)-i >= 8 && binary.LittleEndian.Uint64(b[i:])&0x8080808080808080 == 0 {
		i += 8
	}
	for i < len(b) && b[i] < 0x80 {
		i++
	}
	return i
}

// asciiPrefixString の8byte変換は読取り専用で、結果のsliceを保持しない。
func asciiPrefixString(s string) int {
	i := 0
	for len(s)-i >= 8 && binary.LittleEndian.Uint64([]byte(s[i:i+8]))&0x8080808080808080 == 0 {
		i += 8
	}
	for i < len(s) && s[i] < 0x80 {
		i++
	}
	return i
}
