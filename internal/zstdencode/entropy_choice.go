// 参照列ごとの実符号長でFSE精度を選び、探索とliteral圧縮の再実行を省く。
package zstdencode

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
		}
		if cost < bestBits {
			bestLog, bestBits = log, cost
		}
	}
	return bestLog
}
