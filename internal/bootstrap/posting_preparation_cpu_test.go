// 所有列もCPU構築へ参加し、1/2/4コアで全件完了・順序・同時実行上限を維持することを検査する。
package bootstrap

import (
	"oimobbs/internal/postcapture"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestPostingPreparationOwnerParticipatesWithinCPUBound(t *testing.T) {
	previous := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(previous)
	for _, cpus := range []int{1, 2, 4} {
		runtime.GOMAXPROCS(cpus)
		g := &postingGroup{ctx: t.Context()}
		var active, peak, completed atomic.Int32
		for i := 0; i < 64; i++ {
			g.current = i
			g.addPreparation(uint64(i+1), func() ([]byte, []byte, *postcapture.Capture, error) {
				n := active.Add(1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				runtime.Gosched()
				active.Add(-1)
				return []byte{byte(i)}, nil, nil, nil
			}, func(raw, _ []byte, _ *postcapture.Capture, err error) (any, error) {
				if active.Load() != 0 || err != nil || int(raw[0]) != int(completed.Load()) {
					t.Error("applied before join or out of order", cpus, i, err)
				}
				completed.Add(1)
				return i, err
			}, func() {})
		}
		g.finishPreparations()
		g.joinPreparationWorkers()
		if completed.Load() != 64 || active.Load() != 0 || peak.Load() > int32(cpus) {
			t.Fatal("CPU bound or lifetime", cpus, completed.Load(), active.Load(), peak.Load())
		}
	}
}
