// 参照列の実符号長で定義済み表とFSE精度を選び、探索とliteral圧縮の再実行を省く。
package zstdencode

import "math/bits"

// bestEntropyTable は表header・最終状態・全遷移のbit数が最小の表を保持する。
// 列の状態遷移は互いに独立するため、全精度の組合せを符号化する必要はない。
// codedが1件以上ある列だけから呼ぶ。
func (e *Encoder) bestEntropyTable(counts []int, column int) entropyTable {
	maximum := uint(9)
	if column == 1 {
		maximum = 8
	}
	best := predefinedTables[column]
	bestBits := e.entropyCost(best, column)
	present, last := 0, 0
	for symbol, count := range counts {
		if count > 0 {
			present++
			last = symbol
		}
	}
	counts = counts[:last+1]
	if present == 1 {
		table := entropyTableWithWork(counts, 5, &e.fseWork[column])
		if e.entropyCost(table, column) <= bestBits {
			return table
		}
		return best
	}
	for log := uint(5); log <= maximum; log++ {
		if present > 1<<log {
			continue
		}
		table, possible := e.entropyCandidate(counts, log, column, bestBits)
		if !possible {
			continue
		}
		cost := len(table.header)*8 + int(table.log)
		state := table.start(int(e.coded[len(e.coded)-1].symbol[column]))
		for i := len(e.coded) - 2; i >= 0; i-- {
			var width uint
			state, width = table.transition(int(e.coded[i].symbol[column]), state)
			cost += int(width)
			if cost >= bestBits {
				break
			}
		}
		if cost < bestBits {
			bestBits = cost
			best = retainEntropyTable(table, &e.fseWork[column])
		}
	}
	return best
}

// entropyCandidate は最小の遷移幅でも現最良値に届かない表の構築を省く。
// 頻度は末尾の0を除去済み。最後の記号は初期状態だけで表し、遷移数から除く。
func (e *Encoder) entropyCandidate(counts []int, log uint, column, bestBits int) (entropyTable, bool) {
	work := &e.trialWork
	norm := distributionInto(counts, log, work.norm[:len(counts)])
	header := describeDistributionInto(norm, log, work.header[:])
	minimum := len(header)*8 + int(log)
	last := int(e.coded[len(e.coded)-1].symbol[column])
	for symbol, n := range norm {
		if n == 0 {
			continue
		}
		width := int(log) - bits.Len(uint(n-1))
		occurrences := counts[symbol]
		if symbol == last {
			occurrences--
		}
		minimum += occurrences * width
	}
	if minimum >= bestBits {
		return entropyTable{}, false
	}
	return entropyTableFromNorm(norm, log, header, work), true
}

// retainEntropyTable は採用した表の参照先だけを保存し、同じ表の再構築を省く。
func retainEntropyTable(table entropyTable, work *entropyWork) entropyTable {
	copy(work.first[:], table.first)
	copy(work.symbols[:], table.symbols)
	copy(work.header[:], table.header)
	if cap(work.arena) < len(table.arena) {
		work.arena = make([]uint16, len(table.arena))
	} else {
		work.arena = work.arena[:len(table.arena)]
	}
	copy(work.arena, table.arena)
	return entropyTable{log: table.log, first: work.first[:len(table.first)], arena: work.arena, symbols: work.symbols[:len(table.symbols)], header: work.header[:len(table.header)], single: table.single}
}

// bestEntropyLog は表header・最終状態・全遷移のbit数が最小になる精度を返す。
// 列の状態遷移は互いに独立するため、全精度の組合せを符号化する必要はない。
// codedが1件以上ある列だけから呼ぶ。
func (e *Encoder) bestEntropyLog(counts []int, column int) uint {
	maximum := uint(9)
	if column == 1 {
		maximum = 8
	}
	bestLog, bestBits := uint(5), int(^uint(0)>>1)
	present := 0
	for _, count := range counts {
		if count > 0 {
			present++
		}
	}
	if present == 1 {
		return 5
	}
	for log := uint(5); log <= maximum; log++ {
		if present > 1<<log {
			continue
		}
		table := entropyTableWithWork(counts, log, &e.trialWork)
		cost := len(table.header)*8 + int(table.log)
		state := table.start(int(e.coded[len(e.coded)-1].symbol[column]))
		for i := len(e.coded) - 2; i >= 0; i-- {
			var width uint
			state, _, width = table.advance(int(e.coded[i].symbol[column]), state)
			cost += int(width)
			// 残る遷移幅は非負。同点では先行精度を選ぶため、以後の比較は不要。
			if cost >= bestBits {
				break
			}
		}
		if cost < bestBits {
			bestLog, bestBits = log, cost
		}
	}
	return bestLog
}
