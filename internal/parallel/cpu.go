// Package parallel は所有列が終了を待つ、CPU数以内の一時的な独立作業を実行する。
package parallel

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// CPU は各indexを一度ずつ実行し、全作業完了まで戻らない。呼出元もworkerとして参加する。
// workはindexごとの私的な出力だけを書き、所有状態や保存fileを変更してはならない。
// 件数・保持byteの予算と結果の入力順照合は呼出元で保証する。
func CPU(count int, work func(int)) {
	workers := min(count, runtime.GOMAXPROCS(0))
	if workers <= 1 {
		for i := 0; i < count; i++ {
			work(i)
		}
		return
	}
	var next atomic.Int64
	run := func() {
		for {
			i := int(next.Add(1) - 1)
			if i >= count {
				return
			}
			work(i)
		}
	}
	var pending sync.WaitGroup
	for i := 1; i < workers; i++ {
		pending.Go(run)
	}
	run()
	pending.Wait()
}
