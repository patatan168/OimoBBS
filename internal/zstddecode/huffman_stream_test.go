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
				got := make([]byte, count+1)
				got[count] = 0xaa
				gotErr := decodeHuffmanStream(data, got[:count], table, depth)
				if (wantErr == nil) != (gotErr == nil) || gotErr == nil && !bytes.Equal(got[:count], want) || got[count] != 0xaa {
					t.Fatalf("depth=%d size=%d count=%d: want=%v got=%v", depth, size, count, wantErr, gotErr)
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
