// CPU上限と全indexの一度だけの実行、終了時のworker回収を検証する。
package parallel

import (
	"runtime"
	"sync/atomic"
	"testing"
)

func TestCPUOwnershipAndBound(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	for _, count := range []int{0, 1, 2, 64} {
		visits := make([]atomic.Int32, count)
		var active, peak atomic.Int32
		CPU(count, func(i int) {
			n := active.Add(1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			visits[i].Add(1)
			runtime.Gosched()
			active.Add(-1)
		})
		if active.Load() != 0 || peak.Load() > int32(min(4, count)) {
			t.Fatal("worker lifetime/bound", active.Load(), peak.Load())
		}
		for i := range visits {
			if visits[i].Load() != 1 {
				t.Fatal("index ownership", i, visits[i].Load())
			}
		}
	}
}
