// 候補構築のCPU分担・全件join・所有列への順序反映・取消時の予約返却を検査する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/postcapture"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
)

func TestPostingPreparationJoinsBeforeOrderedApply(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	g := &postingGroup{}
	t.Cleanup(g.joinPreparationWorkers)
	entered := make(chan struct{}, 4)
	unblock := make(chan struct{})
	done := make(chan struct{})
	var released, applied atomic.Int32
	var order []int
	for i := 0; i < 4; i++ {
		g.current, g.ctx = i, t.Context()
		g.addPreparation(uint64(i+1), func() ([]byte, []byte, *postcapture.Capture, error) {
			entered <- struct{}{}
			<-unblock
			return []byte{byte(i)}, nil, nil, nil
		}, func(frame, _ []byte, _ *postcapture.Capture, err error) (any, error) {
			if err != nil || int(frame[0]) != i || g.current != i {
				t.Error("wrong owner result", i, err)
			}
			applied.Add(1)
			order = append(order, i)
			return i, nil
		}, func() { released.Add(1) })
	}
	g.current = 99
	go func() { g.finishPreparations(); close(done) }()
	for range 4 {
		<-entered
	}
	if applied.Load() != 0 || released.Load() != 0 {
		t.Fatal("applied or released before all work completed")
	}
	close(unblock)
	<-done
	if applied.Load() != 4 || released.Load() != 4 || !slices.Equal(order, []int{0, 1, 2, 3}) || g.current != 99 || len(g.preparations) != 0 || len(g.pendingKeys) != 0 {
		t.Fatal("join/order/reservations", order, g.current)
	}
	for i := range 4 {
		if g.preparedResults[i].Value != i {
			t.Fatal("result index", i)
		}
	}
}

func TestPostingPreparationCancellationAndCapacityFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	g := &postingGroup{ctx: ctx, full: true}
	t.Cleanup(g.joinPreparationWorkers)
	released := false
	g.addPreparation(1, func() ([]byte, []byte, *postcapture.Capture, error) {
		t.Error("canceled work executed")
		return nil, nil, nil, nil
	}, func(_, _ []byte, _ *postcapture.Capture, err error) (any, error) { return nil, err }, func() { released = true })
	g.finishPreparations()
	if !released || g.full || !errors.Is(g.preparedResults[0].Err, context.Canceled) {
		t.Fatal("canceled reservation", released, g.preparedResults)
	}
}

// 収集中から有界に実行し、全構築終了後に適用する。保存群内だけworkerを再利用する。
func TestPostingPreparationStartsDuringCollectionAndClosesWorkers(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	g := &postingGroup{ctx: t.Context()}
	t.Cleanup(g.joinPreparationWorkers)
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var active, peak, released atomic.Int32
	var order []int
	for i := range 8 {
		g.current = i
		g.addPreparation(uint64(i+1), func() ([]byte, []byte, *postcapture.Capture, error) {
			n := active.Add(1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			entered <- struct{}{}
			<-release
			active.Add(-1)
			return []byte{byte(i)}, nil, nil, nil
		}, func(frame, _ []byte, _ *postcapture.Capture, err error) (any, error) {
			if active.Load() != 0 || released.Load() < 1 {
				t.Error("applied before all builds joined")
			}
			order = append(order, int(frame[0]))
			return i, err
		}, func() { released.Add(1) })
	}
	// 収集中は3workerが開始し、finish後は所有列も参加してCPU4枠以内で処理する。
	for range 3 {
		select {
		case <-entered:
		case <-t.Context().Done():
			t.Fatal("work did not begin during collection")
		}
	}
	if active.Load() != 3 || released.Load() != 0 || g.preparationWorkerCount != 3 {
		t.Fatal("worker/memory bound", active.Load(), released.Load(), g.preparationWorkerCount)
	}
	close(release)
	g.current = 99
	g.finishPreparations()
	if (peak.Load() < 3 || peak.Load() > 4) || released.Load() != 8 || g.preparationQueue == nil || g.preparationWorkerCount != 3 || g.current != 99 || !slices.Equal(order, []int{0, 1, 2, 3, 4, 5, 6, 7}) {
		t.Fatal("join/order/close", order, peak.Load(), released.Load())
	}
}

// 同じスレッドを含む次群も全構築を待ち、保存境界ではworkerを残さない。
func TestPostingPreparationReusesPoolUntilFlush(t *testing.T) {
	g := &postingGroup{ctx: t.Context(), batch: &app.PostingBatch{}}
	t.Cleanup(g.joinPreparationWorkers)
	var old chan *postingPreparation
	for i := range 3 {
		g.current = i
		g.addPreparation(1, func() ([]byte, []byte, *postcapture.Capture, error) { return []byte{byte(i)}, nil, nil, nil },
			func(raw, _ []byte, _ *postcapture.Capture, err error) (any, error) {
				if err != nil || raw[0] != byte(i) {
					t.Error("unjoined work", err)
				}
				return i, err
			}, func() {})
		if i > 0 && g.preparationQueue != old {
			t.Fatal("pool not reused")
		}
		old = g.preparationQueue
		g.finishPreparations()
	}
	g.flush()
	if g.preparationQueue != nil || g.preparationWorkerCount != 0 {
		t.Fatal("workers survived flush")
	}
}
