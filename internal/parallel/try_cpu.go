// 大きなJSON内の分担処理で追加workerを共有し、同時要求による増殖を抑える。
package parallel

import (
	"runtime"
	"sync"
	"sync/atomic"
)

var extraCPUWorkers atomic.Int64

// TryCPU は追加worker枠を即時に確保できた場合だけ各indexを一度実行する。
// 呼出元も参加し、全workerの終了後に枠を返す。falseならworkは一度も呼ばない。
// workは独立した私的出力だけを書き、再帰的な並列化は呼出元で避ける。
func TryCPU(workers int, work func(int)) bool {
	if workers < 2 {
		return false
	}
	n := int64(workers - 1)
	limit := int64(runtime.GOMAXPROCS(0) - 1)
	for {
		active := extraCPUWorkers.Load()
		if n > limit-active {
			return false
		}
		if extraCPUWorkers.CompareAndSwap(active, active+n) {
			break
		}
	}
	defer extraCPUWorkers.Add(-n)
	var pending sync.WaitGroup
	for i := 1; i < workers; i++ {
		pending.Go(func() { work(i) })
	}
	defer pending.Wait()
	work(0)
	return true
}
