// 費用比較の早期打切りを、全遷移を読む参照計算と照合する。
package zstdencode

import (
	"testing"

	"oimobbs/internal/testutil"
)

func TestEntropyLogPruningKeepsChoice(t *testing.T) {
	for _, kind := range []string{"text", "mixed", "entropy"} {
		var e Encoder
		raw := testutil.DATFixture(kind)
		e.parse(raw, 0, min(len(raw), blockLimit), [3]int{1, 4, 8})
		for column, symbols := range []int{36, 21, 53} {
			counts := e.counts[column][:symbols]
			maximum := uint(9)
			if column == 1 {
				maximum = 8
			}
			best, cost := uint(5), int(^uint(0)>>1)
			for log := uint(5); log <= maximum; log++ {
				table := entropyTableWithWork(counts, log, &e.trialWork)
				if n := e.entropyCost(table, column); n < cost {
					best, cost = log, n
				}
			}
			if got := e.bestEntropyLog(counts, column); got != best {
				t.Fatalf("%s column=%d log=%d want=%d", kind, column, got, best)
			}
		}
	}
}
