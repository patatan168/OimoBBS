// 4本のbit列を交互に復号しても、個別復号の結果と終端検査が一致することを検査する。
package zstddecode

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestHuffmanFourReference(t *testing.T) {
	rng := rand.New(rand.NewSource(84))
	for depth := 1; depth <= 11; depth++ {
		table := make([]huffmanCell, 1<<uint(depth))
		for i := range table {
			table[i] = huffmanCell{byte(i), uint8(depth)}
		}
		for _, count := range []int{0, 1, 3, 15, 16, 17, 31, 32, 63, 64, 127, 1024, 4096} {
			var data [4][]byte
			var sizes [4]int
			for stream := range data {
				sizes[stream] = count + stream
				nbits := sizes[stream] * depth
				data[stream] = make([]byte, (nbits+8)/8)
				rng.Read(data[stream])
				last := len(data[stream]) - 1
				data[stream][last] &= byte((1 << uint(nbits&7)) - 1)
				data[stream][last] |= 1 << uint(nbits&7)
			}
			compareHuffmanFour(t, data, sizes, table, depth)
			for stream := range data {
				copyData := data
				copyData[stream] = bytes.Clone(data[stream])
				copyData[stream][len(copyData[stream])-1] = 0
				compareHuffmanFour(t, copyData, sizes, table, depth)
				copyData[stream] = copyData[stream][:len(copyData[stream])-1]
				compareHuffmanFour(t, copyData, sizes, table, depth)
			}
		}
	}
}

// TestHuffmanFourVariableWidths は4文字ずつの読取りを、長さの異なる有効な符号で照合する。
func TestHuffmanFourVariableWidths(t *testing.T) {
	table := []huffmanCell{{0, 1}, {0, 1}, {0, 1}, {0, 1}, {1, 2}, {1, 2}, {2, 3}, {3, 3}}
	codes, widths := [4]int{0, 2, 6, 7}, [4]int{1, 2, 3, 3}
	for _, count := range []int{0, 1, 3, 15, 16, 17, 31, 32, 63, 64, 127, 1024, 4096} {
		var data [4][]byte
		var sizes [4]int
		for stream := range data {
			sizes[stream] = count + stream
			position := 0
			for i := range sizes[stream] {
				position += widths[(i+stream)%4]
			}
			data[stream] = make([]byte, (position+8)/8)
			data[stream][position/8] = 1 << uint(position%8)
			for i := range sizes[stream] {
				symbol := (i + stream) % 4
				position -= widths[symbol]
				for bit := range widths[symbol] {
					if codes[symbol]>>uint(bit)&1 != 0 {
						at := position + bit
						data[stream][at/8] |= 1 << uint(at%8)
					}
				}
			}
		}
		compareHuffmanFour(t, data, sizes, table, 3)
		for stream := range data {
			bad := data
			bad[stream] = bad[stream][:len(bad[stream])-1]
			compareHuffmanFour(t, bad, sizes, table, 3)
		}
	}
}

func compareHuffmanFour(t *testing.T, data [4][]byte, sizes [4]int, table []huffmanCell, depth int) {
	t.Helper()
	var want, got [4][]byte
	wantOK := true
	for i := range data {
		want[i] = make([]byte, sizes[i])
		got[i] = make([]byte, sizes[i]+1)
		got[i][sizes[i]] = 0xaa
		if referenceHuffmanStream(data[i], want[i], table, depth) != nil {
			wantOK = false
		}
	}
	var out [4][]byte
	for i := range out {
		out[i] = got[i][:sizes[i]]
	}
	err := decodeHuffmanFour(data, out, table, depth)
	if (err == nil) != wantOK {
		t.Fatalf("depth=%d sizes=%v: reference=%v got=%v", depth, sizes, wantOK, err)
	}
	for i := range got {
		if got[i][sizes[i]] != 0xaa || err == nil && !bytes.Equal(out[i], want[i]) {
			t.Fatalf("depth=%d sizes=%v stream=%d: output mismatch", depth, sizes, i)
		}
	}
}
