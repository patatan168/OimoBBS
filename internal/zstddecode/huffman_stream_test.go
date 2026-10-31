// Huffmanの先読み処理を、1symbolずつbitを取り出す参照処理と照合する。
package zstddecode

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestHuffmanStreamReference(t *testing.T) {
	rng := rand.New(rand.NewSource(81))
	for depth := 1; depth <= 11; depth++ {
		table := make([]huffmanCell, 1<<uint(depth))
		for i := range table {
			table[i] = huffmanCell{byte(i), uint8(i%depth + 1)}
		}
		for size := 0; size <= 80; size++ {
			data := make([]byte, size)
			rng.Read(data)
			for count := 0; count <= 80; count++ {
				want := make([]byte, count)
				wantErr := referenceHuffmanStream(data, want, table, depth)
				for _, decode := range []func([]byte, []byte, []huffmanCell, int) error{decodeHuffmanStream, decodeHuffmanSingleStream} {
					got := make([]byte, count+1)
					got[count] = 0xaa
					gotErr := decode(data, got[:count], table, depth)
					if (wantErr == nil) != (gotErr == nil) || gotErr == nil && !bytes.Equal(got[:count], want) || got[count] != 0xaa {
						t.Fatalf("depth=%d size=%d count=%d: want=%v got=%v", depth, size, count, wantErr, gotErr)
					}
				}
			}
		}
	}
}

// referenceHuffmanStream は先読みを行わず、残りbitごとに元の検査を行う。
func referenceHuffmanStream(data, out []byte, table []huffmanCell, depth int) error {
	b, err := reverseStream(data)
	if err != nil {
		return err
	}
	for i := range out {
		width := min(depth, b.position)
		value := b.extract(b.position-width, width) << uint(depth-width)
		cell := table[value]
		if cell.width == 0 || int(cell.width) > b.position || b.invalid {
			return ErrInvalid
		}
		b.position -= int(cell.width)
		out[i] = cell.symbol
	}
	if b.position != 0 {
		return ErrInvalid
	}
	return nil
}

// FuzzHuffmanStreamReference は長短の符号と任意bit列を単純な参照復号器へ照合する。
func FuzzHuffmanStreamReference(f *testing.F) {
	for _, seed := range [][]byte{{1}, {0, 1}, {255, 1}, {1, 2, 3, 128}} {
		f.Add(seed, uint16(17), uint8(9))
	}
	f.Fuzz(func(t *testing.T, data []byte, count uint16, selector uint8) {
		if len(data) > 16384 {
			t.Skip()
		}
		depth := 1 + int(selector%11)
		table := make([]huffmanCell, 1<<uint(depth))
		for symbol := 0; symbol <= depth; symbol++ {
			width := min(symbol+1, depth)
			code := (1 << uint(width)) - 2
			if symbol == depth {
				code++
			}
			start, end := code<<uint(depth-width), (code+1)<<uint(depth-width)
			for i := start; i < end; i++ {
				table[i] = huffmanCell{byte(symbol), uint8(width)}
			}
		}
		size := int(count % 4097)
		want := make([]byte, size)
		expected := referenceHuffmanStream(data, want, table, depth)
		output := make([]byte, size+1)
		output[size] = 0xaa
		actual := decodeHuffmanSingleStream(data, output[:size], table, depth)
		if (expected == nil) != (actual == nil) || actual == nil && !bytes.Equal(output[:size], want) || output[size] != 0xaa {
			t.Fatal("Huffman output or rejection differs", expected, actual)
		}
	})
}
