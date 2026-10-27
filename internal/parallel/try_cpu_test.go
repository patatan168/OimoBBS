// 同時要求の共有worker上限と、枠不足時の無実行・終了後の返却を検証する。
package parallel

import (
	"runtime"
	"sync/atomic"
	"testing"
)

func TestTryCPUSharedBudget(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	visits := make([]atomic.Int32, 4)
	go func() {
		done <- TryCPU(4, func(i int) {
			visits[i].Add(1)
			if i == 0 {
				close(entered)
				<-release
			}
		})
	}()
	<-entered
	called := false
	accepted := TryCPU(2, func(int) { called = true })
	close(release)
	if !<-done || accepted || called || extraCPUWorkers.Load() != 0 {
		t.Fatal("shared budget or worker release", accepted, called, extraCPUWorkers.Load())
	}
	for i := range visits {
		if visits[i].Load() != 1 {
			t.Fatal("index not executed exactly once", i, visits[i].Load())
		}
	}
	for _, workers := range []int{0, 1, 5} {
		if TryCPU(workers, func(int) { t.Error("unexpected work") }) {
			t.Fatal("invalid worker count accepted", workers)
		}
	}
	if !TryCPU(4, func(int) {}) {
		t.Fatal("worker budget leaked")
	}
}
