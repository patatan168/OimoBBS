// 独立検証の並行実行と、全結果照合前に所有状態を更新しないことを検査する。
package bootstrap

import (
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestPostingCandidateChecksUseCPUsAndJoin(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	failure := errors.New("bad candidate")
	g := &postingGroup{rejected: map[int]error{}}
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	done := make(chan struct{})
	var active atomic.Int32
	for i := 0; i < 4; i++ {
		g.validations = append(g.validations, postingValidation{index: i, check: func() error {
			active.Add(1)
			entered <- struct{}{}
			<-release
			active.Add(-1)
			if i == 2 {
				return failure
			}
			return nil
		}})
	}
	go func() { g.validateCandidates(); close(done) }()
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-t.Context().Done():
			t.Fatal("workers did not start")
		}
	}
	if len(g.rejected) != 0 {
		t.Fatal("worker changed owner state")
	}
	close(release)
	<-done
	if active.Load() != 0 || !g.rebuild || len(g.rejected) != 1 || !errors.Is(g.rejected[2], failure) {
		t.Fatal("candidate results", g.rejected, active.Load())
	}
}
