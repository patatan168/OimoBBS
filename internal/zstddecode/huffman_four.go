// 独立した4本のHuffman列を交互に復号し、表参照の待ち時間を重ねる。
package zstddecode

// decodeHuffmanFour は検査済みprefix表を使い、各出力の長さと各列の終端を維持する。
func decodeHuffmanFour(data, out [4][]byte, table []huffmanCell, depth int) error {
	common := min(len(out[0]), len(out[1]), len(out[2]), len(out[3]))
	if common < 16 {
		for i := range data {
			if err := decodeHuffmanStream(data[i], out[i], table, depth); err != nil {
				return err
			}
		}
		return nil
	}
	var positions, available [4]int
	var words [4]uint64
	for i := range data {
		b, err := reverseStream(data[i])
		if err != nil {
			return err
		}
		positions[i] = b.position
	}
	shift := uint(64 - depth)
	i := 0
	// 4文字分のbitを先に確保し、通常部分の補充検査を4回に1回へまとめる。
	for i+4 <= common {
		for stream := range data {
			if available[stream] < 4*depth && available[stream] < positions[stream] {
				words[stream], available[stream] = reverseWindow(data[stream], positions[stream])
			}
		}
		if min(available[0], available[1], available[2], available[3]) < 4*depth {
			break
		}
		for end := i + 4; i < end; i++ {
			c0 := table[words[0]>>shift]
			c1 := table[words[1]>>shift]
			c2 := table[words[2]>>shift]
			c3 := table[words[3]>>shift]
			w0, w1, w2, w3 := int(c0.width), int(c1.width), int(c2.width), int(c3.width)
			// huffmanTableは全cellを幅1〜depthで埋める。先読み済みの4*depth bit内に収まる。
			words[0] <<= uint(w0)
			words[1] <<= uint(w1)
			words[2] <<= uint(w2)
			words[3] <<= uint(w3)
			available[0] -= w0
			available[1] -= w1
			available[2] -= w2
			available[3] -= w3
			positions[0] -= w0
			positions[1] -= w1
			positions[2] -= w2
			positions[3] -= w3
			out[0][i], out[1][i], out[2][i], out[3][i] = c0.symbol, c1.symbol, c2.symbol, c3.symbol
		}
	}
	for ; i < common; i++ {
		for stream := range data {
			if available[stream] < depth && available[stream] < positions[stream] {
				words[stream], available[stream] = reverseWindow(data[stream], positions[stream])
			}
		}
		c0 := table[words[0]>>shift]
		c1 := table[words[1]>>shift]
		c2 := table[words[2]>>shift]
		c3 := table[words[3]>>shift]
		w0, w1, w2, w3 := int(c0.width), int(c1.width), int(c2.width), int(c3.width)
		if w0 == 0 || w0 > available[0] || w1 == 0 || w1 > available[1] || w2 == 0 || w2 > available[2] || w3 == 0 || w3 > available[3] {
			return ErrInvalid
		}
		words[0] <<= uint(w0)
		words[1] <<= uint(w1)
		words[2] <<= uint(w2)
		words[3] <<= uint(w3)
		available[0] -= w0
		available[1] -= w1
		available[2] -= w2
		available[3] -= w3
		positions[0] -= w0
		positions[1] -= w1
		positions[2] -= w2
		positions[3] -= w3
		out[0][i], out[1][i], out[2][i], out[3][i] = c0.symbol, c1.symbol, c2.symbol, c3.symbol
	}
	for i := range data {
		if err := decodeHuffmanRemaining(data[i], out[i][common:], table, depth, positions[i], words[i], available[i]); err != nil {
			return err
		}
	}
	return nil
}
