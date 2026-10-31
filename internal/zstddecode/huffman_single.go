// 短いframeの単一Huffman列を4文字ずつ先読みし、入力境界と終端を検査する。
package zstddecode

// decodeHuffmanSingleStream は検証済みの表を使い、十分なbitがある区間だけ幅検査をまとめる。
func decodeHuffmanSingleStream(data, out []byte, table []huffmanCell, depth int) error {
	b, err := reverseStream(data)
	if err != nil {
		return err
	}
	position, word, available := b.position, uint64(0), 0
	i := 0
	shift := uint(64 - depth)
	// 表は幅1〜depthで検証済み。4文字分を先読みできた区間だけ検査をまとめる。
	for i+4 <= len(out) {
		if available < 4*depth && available < position {
			word, available = reverseWindow(data, position)
		}
		if available < 4*depth {
			break
		}
		consumed := 0
		for end := i + 4; i < end; i++ {
			cell := table[word>>shift]
			width := int(cell.width)
			word <<= uint(width)
			available -= width
			consumed += width
			out[i] = cell.symbol
		}
		position -= consumed
	}
	for ; i < len(out); i++ {
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
