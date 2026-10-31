// FSE候補の構築前除外を、全候補を完全構築する参照選択と比較する。
package zstdencode

import (
	"math/rand/v2"
	"reflect"
	"testing"
)

// TestEntropyPruningMatchesExhaustive は空でない列の全精度とtieの採用順を照合する。
func TestEntropyPruningMatchesExhaustive(t *testing.T) {
	rng := rand.New(rand.NewPCG(739, 613))
	for _, size := range []int{1, 2, 3, 7, 15, 31, 64, 257, 1024} {
		for _, skew := range []int{1, 2, 8} {
			var e Encoder
			for range size {
				var code sequenceCode
				for column, alphabet := range []int{36, 21, 53} {
					symbol := 0
					if rng.IntN(skew) == 0 {
						symbol = rng.IntN(alphabet)
					}
					code.symbol[column] = uint8(symbol)
					e.counts[column][symbol]++
				}
				e.coded = append(e.coded, code)
			}
			assertEntropyPruning(t, &e)
		}
	}
}

// FuzzEntropyPruning は順序・分布が異なる列でも全候補との一致を確認する。
func FuzzEntropyPruning(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{0, 1, 2, 3, 4, 31, 32, 35, 52})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 52, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 1024 {
			t.Skip()
		}
		var e Encoder
		for _, v := range data {
			var code sequenceCode
			for column, alphabet := range []int{36, 21, 53} {
				symbol := int(v) % alphabet
				code.symbol[column] = uint8(symbol)
				e.counts[column][symbol]++
			}
			e.coded = append(e.coded, code)
		}
		assertEntropyPruning(t, &e)
	})
}

// assertEntropyPruning は未出現symbolの未使用領域を除き、wireに影響する全要素を照合する。
func assertEntropyPruning(t *testing.T, e *Encoder) {
	t.Helper()
	for column, alphabet := range []int{36, 21, 53} {
		counts := e.counts[column][:alphabet]
		got := e.bestEntropyTable(counts, column)
		want := exhaustiveEntropyTable(e, counts, column)
		// 未出現symbolの作業領域は、構築を省いた回数で残る値が変わる。
		got.symbols = append([]entropySymbol(nil), got.symbols...)
		want.symbols = append([]entropySymbol(nil), want.symbols...)
		for symbol := range got.symbols {
			if symbol >= len(counts) || counts[symbol] == 0 {
				got.symbols[symbol], want.symbols[symbol] = entropySymbol{}, entropySymbol{}
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("size=%d column=%d: selected table changed", len(e.coded), column)
		}
	}
}

// exhaustiveEntropyTable は全候補の正確な費用を計算し、下限による除外を行わない。
func exhaustiveEntropyTable(e *Encoder, counts []int, column int) entropyTable {
	best := predefinedTables[column]
	bestBits := e.entropyCost(best, column)
	var trial, keep entropyWork
	present := 0
	for _, n := range counts {
		if n > 0 {
			present++
		}
	}
	if present == 1 {
		table := entropyTableWithWork(counts, 5, &keep)
		if e.entropyCost(table, column) <= bestBits {
			return table
		}
		return best
	}
	maximum := uint(9)
	if column == 1 {
		maximum = 8
	}
	for log := uint(5); log <= maximum; log++ {
		if present > 1<<log {
			continue
		}
		table := entropyTableWithWork(counts, log, &trial)
		cost := e.entropyCost(table, column)
		if cost < bestBits {
			bestBits = cost
			best = retainEntropyTable(table, &keep)
		}
	}
	return best
}
