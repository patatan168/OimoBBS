// 表の深さが頻出範囲なら、同じ検査を行う定数深さ版へ振り分ける。
package zstddecode

//go:generate python3 ../../tools/generate-zstd-huffman.py

// decodeHuffmanFour は検証済みの深さと表長から、定数shiftの実装を一度だけ選ぶ。
func decodeHuffmanFour(data, out [4][]byte, table []huffmanCell, depth int) error {
	switch depth {
	case 6:
		return decodeHuffmanFourDepth6(data, out, (*[64]huffmanCell)(table))
	case 7:
		return decodeHuffmanFourDepth7(data, out, (*[128]huffmanCell)(table))
	case 8:
		return decodeHuffmanFourDepth8(data, out, (*[256]huffmanCell)(table))
	case 9:
		return decodeHuffmanFourDepth9(data, out, (*[512]huffmanCell)(table))
	case 10:
		return decodeHuffmanFourDepth10(data, out, (*[1024]huffmanCell)(table))
	case 11:
		return decodeHuffmanFourDepth11(data, out, (*[2048]huffmanCell)(table))
	default:
		return decodeHuffmanFourGeneric(data, out, table, depth)
	}
}
