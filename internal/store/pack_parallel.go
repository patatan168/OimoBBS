// 独立したpackブロックの展開・検証を分担し、順序と補助worker数の上限を保つ。
package store

import (
	"runtime"
	"sync"
	"sync/atomic"
)

var packDecodeWorkers atomic.Int32

// visitPackBlocks は大きい複数ブロックだけを最大4workerで処理する。
// visitはindexごとに専有領域へ書く。全workerを待ち、最初のindexのエラーを返す。
// 補助worker枠は全要求で共有し、枠不足なら呼出元だけで進める。
func visitPackBlocks(blocks []packBlock, visit func(int) error) error {
	var raw uint64
	for _, block := range blocks {
		raw += uint64(block.chunk.RawLength)
	}
	limit := min(4, runtime.GOMAXPROCS(0), len(blocks)) - 1
	var reserved int32
	if raw >= 128<<10 {
		for range max(0, limit) {
			active := packDecodeWorkers.Load()
			if active >= int32(min(3, runtime.GOMAXPROCS(0)-1)) || !packDecodeWorkers.CompareAndSwap(active, active+1) {
				break
			}
			reserved++
		}
	}
	if reserved == 0 {
		for i := range blocks {
			if err := visit(i); err != nil {
				return err
			}
		}
		return nil
	}
	errors := make([]error, len(blocks))
	var next atomic.Int64
	work := func() {
		for i := int(next.Add(1) - 1); i < len(blocks); i = int(next.Add(1) - 1) {
			errors[i] = visit(i)
		}
	}
	var workers sync.WaitGroup
	for range reserved {
		workers.Go(func() {
			defer packDecodeWorkers.Add(-1)
			work()
		})
	}
	work()
	workers.Wait()
	for _, err := range errors {
		if err != nil {
			return err
		}
	}
	return nil
}
