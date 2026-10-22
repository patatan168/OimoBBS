// Huffman用の逆向きbit列を64bitずつ先読みし、終端を厳密に検査する。
package zstddecode

import "encoding/binary"

// decodeHuffmanStream は検証済みのprefix表で、指定長の出力だけを埋める。
// 先読みは入力slice内に限定し、最終symbol後の余りbitも拒否する。
func decodeHuffmanStream(data, out []byte, table []huffmanCell, depth int) error {
	b, err := reverseStream(data)
	if err != nil {
		return err
	}
	return decodeHuffmanRemaining(data, out, table, depth, b.position, 0, 0)
}

// decodeHuffmanRemaining は先読み済み状態から残りのsymbolと終端を検査する。
func decodeHuffmanRemaining(data, out []byte, table []huffmanCell, depth, position int, word uint64, available int) error {
	for i := range out {
		if available < depth && available < position {
			word, available = reverseWindow(data, position)
		}
		cell := table[word>>uint(64-depth)]
		width := int(cell.width)
		if width == 0 || width > available {
			return ErrInvalid
		}
		word <<= uint(width)
		available -= width
		position -= width
		out[i] = cell.symbol
	}
	if position != 0 {
		return ErrInvalid
	}
	return nil
}

// reverseWindow は検査済みの位置から最大64bitを上位詰めで読む。
// 有効bit数を別に返し、末尾のzero埋めを符号として消費させない。
func reverseWindow(data []byte, position int) (uint64, int) {
	end := (position + 7) / 8
	if end >= 8 {
		extra := end*8 - position
		return binary.LittleEndian.Uint64(data[end-8:end]) << uint(extra), 64 - extra
	}
	var word uint64
	for j, v := range data[:end] {
		word |= uint64(v) << uint(j*8)
	}
	return word << uint(64-position), position
}
