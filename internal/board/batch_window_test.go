// 所有列で群ごとに一度だけ待ち予算を選び、追加収集で予算を復活させないことを確認する。
package board

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestBatchCollectionWindowSelectedOnce は追加収集を繰り返しても群全体の待ち予算が増えないことを確認する。
func TestBatchCollectionWindowSelectedOnce(t *testing.T) {
	for _, window := range []time.Duration{0, 2 * time.Millisecond} {
		t.Run(window.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := NewWorker()
				defer w.Close()
				calls := 0
				prepared := false
				batch := &Batch{CollectWindow: time.Second, CanWait: func() bool { return prepared }, CollectionWindow: func(queued int) time.Duration {
					calls++
					if queued != 0 {
						t.Error("unexpected backlog", queued)
					}
					return window
				}}
				batch.RunReady = func(ops []BatchOperation, collect func() []BatchOperation) []BatchResult {
					results := make([]BatchResult, len(ops))
					for i, op := range ops {
						results[i].Value, results[i].Err = op.Run()
					}
					for range 2 {
						if len(collect()) != 0 {
							t.Error("unexpected operation")
						}
					}
					return results
				}
				started := time.Now()
				_, err := w.SubmitBatch(context.Background(), batch, 1, func() (any, error) { prepared = true; return nil, nil })
				if err != nil || calls != 1 || time.Since(started) != window {
					t.Fatal("collection budget", calls, time.Since(started), err)
				}
			})
		})
	}
}

// TestBatchCollectionWindowReceivesBacklog は所有列で先頭以外の待機数を選択器へ渡す。
func TestBatchCollectionWindowReceivesBacklog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := NewWorker()
		defer w.Close()
		entered, release, firstDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(firstDone)
			w.Submit(context.Background(), func() (any, error) { close(entered); <-release; return nil, nil })
		}()
		<-entered
		var seen []int
		batch := &Batch{CollectionWindow: func(queued int) time.Duration { seen = append(seen, queued); return 0 }, Run: func(ops []BatchOperation) []BatchResult {
			results := make([]BatchResult, len(ops))
			for i, op := range ops {
				results[i].Value, results[i].Err = op.Run()
			}
			return results
		}}
		var finished sync.WaitGroup
		for range 3 {
			finished.Go(func() { w.SubmitBatch(context.Background(), batch, 1, func() (any, error) { return nil, nil }) })
		}
		synctest.Wait()
		close(release)
		finished.Wait()
		<-firstDone
		if len(seen) != 1 || seen[0] != 2 {
			t.Fatal("backlog selection", seen)
		}
	})
}
