// Huffmanの連続2文字を有界なprefix表でまとめ、literalの反復回数を減らす。
package zstddecode

const pairPrefix = 12

// decodeHuffmanPairsFour は検証済みの表から16KiBの共通作業表を作り、4列で再利用する。
// 12bitに2文字が収まらないprefixは1文字だけ進め、末尾は従来の厳密な検査を使う。
func decodeHuffmanPairsFour(data, out [4][]byte, table []huffmanCell, depth int) error {
	var pairs [1 << pairPrefix]uint32
	for prefix := 0; prefix < len(pairs); {
		first := table[prefix>>uint(pairPrefix-depth)]
		width := int(first.width)
		// 下位2byteは文字、次のbyteは消費bit数、上位byteは出力文字数。
		value := uint32(first.symbol) | uint32(width)<<16 | 1<<24
		second := table[(prefix<<uint(width)&(len(pairs)-1))>>uint(pairPrefix-depth)]
		if width+int(second.width) <= pairPrefix {
			value = uint32(first.symbol) | uint32(second.symbol)<<8 | uint32(width+int(second.width))<<16 | 2<<24
		}
		count := 1
		if value>>24 == 2 {
			// 2文字の符号を消費した後のbitは結果に影響しない。
			// 1文字だけの候補は、後続prefixに短い第2符号があるためまとめない。
			count = 1 << uint(pairPrefix-int(value>>16&31))
			count -= prefix & (count - 1)
		}
		for end := prefix + count; prefix < end; prefix++ {
			pairs[prefix] = value
		}
	}
	for stream := range data {
		if err := decodeHuffmanPairs(data[stream], out[stream], &pairs, table, depth); err != nil {
			return err
		}
	}
	return nil
}

// decodeHuffmanPairs は入力内のwordだけを先読みし、最大2文字ずつ専有出力へ書く。
func decodeHuffmanPairs(data, out []byte, pairs *[1 << pairPrefix]uint32, table []huffmanCell, depth int) error {
	b, err := reverseStream(data)
	if err != nil {
		return err
	}
	position, available, word := b.position, 0, uint64(0)
	i := 0
	for i+2 <= len(out) {
		if available < pairPrefix && position > 0 {
			remaining := position + available
			word, available = reverseWindow(data, remaining)
			position = remaining - available
		}
		if available < pairPrefix {
			break
		}
		cell := pairs[word>>(64-pairPrefix)]
		width := int(cell>>16) & 31
		word <<= uint(width)
		available -= width
		out[i] = byte(cell)
		if cell>>24 == 2 {
			out[i+1] = byte(cell >> 8)
			i += 2
		} else {
			i++
		}
	}
	return decodeHuffmanRemaining(data, out[i:], table, depth, position+available, word, available)
}
