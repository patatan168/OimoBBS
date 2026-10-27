// 複数keyの同期共有を明示した所有者でも、通常操作を追い越さないことを検査する。
package board

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestBatchAcrossKeysPreservesArrivalAndNormalBoundary(t *testing.T) {
	for _, across := range []bool{false, true} {
		w := NewWorker()
		entered, unblock := make(chan struct{}), make(chan struct{})
		done := make(chan error, 6)
		go func() {
			_, err := w.Submit(context.Background(), func() (any, error) { close(entered); <-unblock; return nil, nil })
			done <- err
		}()
		<-entered
		var order, sizes []int
		batch := &Batch{AcrossKeys: across, Run: func(ops []BatchOperation) []BatchResult {
			sizes = append(sizes, len(ops))
			results := make([]BatchResult, len(ops))
			for i, op := range ops {
				results[i].Value, results[i].Err = op.Run()
			}
			return results
		}}
		for index := 1; index <= 5; index++ {
			go func() {
				run := func() (any, error) { order = append(order, index); return index, nil }
				var err error
				if index == 3 {
					_, err = w.Submit(context.Background(), run)
				} else {
					_, err = w.SubmitBatch(context.Background(), batch, uint64(index%2+1), run)
				}
				done <- err
			}()
			waitPending(t, w, index+1)
		}
		close(unblock)
		for range 6 {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		w.Close()
		want := []int{1, 1, 1, 1}
		if across {
			want = []int{2, 2}
		}
		if !reflect.DeepEqual(order, []int{1, 2, 3, 4, 5}) || !reflect.DeepEqual(sizes, want) {
			t.Fatal(across, order, sizes)
		}
	}
}

// 一度の期限内でWebのフォーム→確認→確定を集め、保存結果の先返しと無制限待機を防ぐ。
func TestBatchCollectWindowCollectsMultipleFollowups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := NewWorker()
		entered, unblock := make(chan struct{}), make(chan struct{})
		go w.Submit(context.Background(), func() (any, error) { close(entered); <-unblock; return nil, nil })
		<-entered
		var committed atomic.Bool
		prepared := false
		var sizes []int
		batch := &Batch{AcrossKeys: true, CollectWindow: 2 * time.Millisecond, CanWait: func() bool { return prepared }}
		batch.RunReady = func(ops []BatchOperation, collect func() []BatchOperation) []BatchResult {
			var results []BatchResult
			for i := 0; i < len(ops); i++ {
				v, e := ops[i].Run()
				results = append(results, BatchResult{v, e})
				if v != "stored" {
					ops[i].Complete(v, e)
				} else {
					prepared = true
				}
				if i == len(ops)-1 {
					ops = append(ops, collect()...)
				}
			}
			sizes = append(sizes, len(ops))
			committed.Store(true)
			return results
		}
		legacyDone, webDone := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(legacyDone)
			_, e := w.SubmitBatch(context.Background(), batch, 1, func() (any, error) { return "stored", nil })
			if e != nil || !committed.Load() {
				t.Error("保存前の応答", e)
			}
		}()
		synctest.Wait()
		go func() {
			defer close(webDone)
			for _, value := range []string{"form", "confirmation", "stored"} {
				v, e := w.SubmitBatch(context.Background(), batch, 2, func() (any, error) { return value, nil })
				if e != nil || v != value {
					t.Error(v, e)
				}
				if value == "stored" && !committed.Load() {
					t.Error("保存前の応答")
				}
				if value != "stored" {
					time.Sleep(100 * time.Microsecond)
				}
			}
		}()
		synctest.Wait()
		start := time.Now()
		close(unblock)
		<-legacyDone
		<-webDone
		synctest.Wait()
		w.Close()
		if !reflect.DeepEqual(sizes, []int{4}) || time.Since(start) != 2*time.Millisecond {
			t.Fatal("往復を分断したか累積時間の上限を超過", sizes, time.Since(start))
		}
	})
}

// 収集待ち中の通常操作は保存を追い越さず、終了通知は残りの収集時間を待たせない。
func TestBatchCollectWindowNormalBoundaryAndClose(t *testing.T) {
	for _, closing := range []bool{false, true} {
		name := "normal"
		if closing {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := NewWorker()
				prepared, returned := make(chan struct{}), make(chan struct{})
				var order []string
				ready := false
				batch := &Batch{AcrossKeys: true, CollectWindow: time.Second, CanWait: func() bool { return ready }}
				batch.RunReady = func(ops []BatchOperation, collect func() []BatchOperation) []BatchResult {
					var results []BatchResult
					for _, op := range ops {
						v, e := op.Run()
						results = append(results, BatchResult{v, e})
					}
					close(prepared)
					if extra := collect(); len(extra) != 0 {
						t.Error("通常操作を保存群へ混ぜた")
					}
					order = append(order, "commit")
					return results
				}
				go func() {
					defer close(returned)
					w.SubmitBatch(context.Background(), batch, 1, func() (any, error) { order = append(order, "prepare"); ready = true; return nil, nil })
				}()
				<-prepared
				synctest.Wait()
				start := time.Now()
				if closing {
					w.Close()
				} else {
					done := make(chan struct{})
					go func() {
						defer close(done)
						w.Submit(context.Background(), func() (any, error) { order = append(order, "normal"); return nil, nil })
					}()
					<-done
					w.Close()
				}
				<-returned
				expected := []string{"prepare", "commit"}
				if !closing {
					expected = append(expected, "normal")
				}
				if !reflect.DeepEqual(order, expected) || time.Since(start) != 0 {
					t.Fatal("順序か収集の中断を破った", order, time.Since(start))
				}
			})
		})
	}
}
