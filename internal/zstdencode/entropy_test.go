// bit出力のword境界とFSE逆引きの復号契約を独立した計算で検査する。
package zstdencode

import (
	"bytes"
	"math/bits"
	"math/rand/v2"
	"testing"
)

func TestBitWriterCarry(t *testing.T) {
	rng := rand.New(rand.NewPCG(17, 29))
	for prefix := range 64 {
		var writer bitWriter
		var want []byte
		position := 0
		appendBits := func(value uint64, count uint) {
			for i := uint(0); i < count; i++ {
				if position/8 == len(want) {
					want = append(want, 0)
				}
				want[position/8] |= byte((value>>i)&1) << uint(position%8)
				position++
			}
		}
		value := rng.Uint64() & ((uint64(1) << uint(prefix)) - 1)
		// prefixは二回以下の書込みで63bitまで埋める。
		if prefix > 32 {
			writer.put(uint32(value), 32)
			writer.put(uint32(value>>32), uint(prefix-32))
		} else {
			writer.put(uint32(value), uint(prefix))
		}
		appendBits(value, uint(prefix))
		for count := uint(0); count <= 54; count++ {
			value = rng.Uint64() & ((uint64(1) << count) - 1)
			writer.putWide(value, count)
			appendBits(value, count)
		}
		appendBits(1, 1)
		if got := writer.finish(); !bytes.Equal(got, want) {
			t.Fatalf("prefix=%d word carry mismatch", prefix)
		}
	}
}

func TestEntropyInverseAndReuse(t *testing.T) {
	// 実装の逆引き配列ではなく、公開形式の復号遷移から戻り値を検査する。
	type decodeStep struct {
		symbol int
		width  uint
		base   int
	}
	samples := [][]int{{3, 1000, 1, 0, 7, 200, 4000}, {9, 2, 21, 100, 17, 3, 40}, {1, 1, 1, 1, 1, 1, 1, 1}, {100000, 1, 1, 1, 1, 1, 1, 1}}
	for log := uint(5); log <= 9; log++ {
		size := 1 << log
		var work entropyWork
		for _, counts := range samples {
			table := entropyTableWithWork(counts, log, &work)
			norm := distribution(counts, log)
			symbolAt := make([]int, size)
			cursor := 0
			for symbol, frequency := range norm {
				for range frequency {
					symbolAt[cursor] = symbol
					cursor = (cursor + size/2 + size/8 + 3) % size
				}
			}
			next := append([]int(nil), norm...)
			decode := make([]decodeStep, size)
			for state, symbol := range symbolAt {
				rank := next[symbol]
				next[symbol]++
				width := log - uint(bits.Len(uint(rank))-1)
				decode[state] = decodeStep{symbol, width, (rank << width) - size}
			}
			for symbol, frequency := range norm {
				if frequency == 0 {
					continue
				}
				for state := range size {
					previous, value, width := table.advance(symbol, uint16(state))
					d := decode[previous]
					if d.symbol != symbol || d.width != width || d.base+int(value) != state || value >= 1<<width {
						t.Fatalf("log=%d symbol=%d state=%d inverse mismatch", log, symbol, state)
					}
				}
			}
		}
	}
	single := entropyTableWithWork([]int{0, 7, 0}, 7, &entropyWork{})
	if state, value, width := single.advance(1, 0); state != 0 || value != 0 || width != 0 || single.single != 1 {
		t.Fatal("RLE state")
	}
}
