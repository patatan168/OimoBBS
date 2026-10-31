// 標準の定義済みFSE表を起動時に構築し、送信する表headerを省く候補にする。
package zstdencode

import (
	"math/bits"
	"oimobbs/internal/zstdformat"
)

var predefinedTables = buildPredefinedTables()

// buildPredefinedTables は公開の正規化頻度から逆引き表を構成する。
// 構築後は読み取り専用とし、各workerの作業表とは共有しない。
func buildPredefinedTables() [3]entropyTable {
	var tables [3]entropyTable
	for column := range tables {
		norm, log, length := zstdformat.Predefined(column)
		size := 1 << log
		t := entropyTable{log: log, single: -1, first: make([]uint16, length), arena: make([]uint16, size), symbols: make([]entropySymbol, length)}
		var states [64]int
		high, cumulative := size-1, 0
		for symbol, n := range norm[:length] {
			if n < 0 {
				states[high] = symbol
				high--
				n = 1
			}
			width := log - uint(bits.Len(uint(n))-1)
			t.symbols[symbol] = entropySymbol{uint32(width<<16) - uint32(n<<width), int32(cumulative - n)}
			cumulative += n
		}
		position, step := 0, size/2+size/8+3
		for symbol, n := range norm[:length] {
			for range n {
				states[position] = symbol
				position = (position + step) & (size - 1)
				for position > high {
					position = (position + step) & (size - 1)
				}
			}
			if n < 0 {
				norm[symbol] = 1
			}
		}
		for state, symbol := range states[:size] {
			n := norm[symbol]
			norm[symbol]++
			width := log - uint(bits.Len(uint(n))-1)
			if width > 0 {
				t.first[symbol] = uint16(state)
			}
			t.arena[int(t.symbols[symbol].base)+n] = uint16(state)
		}
		tables[column] = t
	}
	return tables
}

// entropyCost はheader・初期状態・全遷移を含むbit数を返す。列は空でないこと。
func (e *Encoder) entropyCost(table entropyTable, column int) int {
	cost := len(table.header)*8 + int(table.log)
	state := table.start(int(e.coded[len(e.coded)-1].symbol[column]))
	for i := len(e.coded) - 2; i >= 0; i-- {
		var width uint
		state, width = table.transition(int(e.coded[i].symbol[column]), state)
		cost += int(width)
	}
	return cost
}
