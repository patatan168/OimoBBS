// 非必須保存の最小間隔と、終了時の即時drainを仮想時計で検査する。
package evidence

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

func TestOptionalBatchPacing(t *testing.T) {
	for _, closing := range []bool{false, true} {
		name := "interval"
		if closing {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				starts := make(chan time.Time, 2)
				q := &OptionalQueue{queue: make(chan *optionalQueuedRecord, MaxOptionalRecords), done: make(chan struct{}), closing: make(chan struct{}), cancel: cancel, batchWait: time.Hour, batchInterval: optionalBatchInterval,
					batchWrite: func(_ context.Context, records []OptionalRecord) []error {
						starts <- time.Now()
						return make([]error, len(records))
					}}
				go func() { defer close(q.done); q.run(ctx) }()
				t.Cleanup(func() { cancel(); q.Close(context.Background()) })
				for range 2 * MaxOptionalBatch {
					if !q.Enqueue(optionalFixture()) {
						t.Fatal("受付失敗")
					}
				}
				synctest.Wait()
				if len(starts) != 1 || q.Status().Saved != MaxOptionalBatch {
					t.Fatal("バックログで最小間隔を迂回した", len(starts), q.Status())
				}
				first := <-starts
				if closing {
					if err := q.Close(context.Background()); err != nil {
						t.Fatal(err)
					}
					if second := <-starts; !second.Equal(first) {
						t.Fatal("終了drainで不要な間隔を待った", second.Sub(first))
					}
				} else {
					time.Sleep(optionalBatchInterval - time.Nanosecond)
					synctest.Wait()
					if len(starts) != 0 {
						t.Fatal("間隔より早く保存した")
					}
					time.Sleep(time.Nanosecond)
					synctest.Wait()
					if second := <-starts; second.Sub(first) != optionalBatchInterval {
						t.Fatal("補充時刻に再開しなかった", second.Sub(first))
					}
					if err := q.Close(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				status := q.Status()
				if status.Accepted != 128 || status.Saved != 128 || status.Pending != 0 || status.Failed != 0 {
					t.Fatal(status)
				}
			})
		})
	}
}

func TestOptionalBatchPacingStartsAfterCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		starts := make(chan time.Time, 2)
		writeTime := 50 * time.Millisecond
		q := &OptionalQueue{queue: make(chan *optionalQueuedRecord, MaxOptionalRecords), done: make(chan struct{}), closing: make(chan struct{}), cancel: cancel, batchWait: time.Hour, batchInterval: optionalBatchInterval,
			batchWrite: func(_ context.Context, records []OptionalRecord) []error {
				starts <- time.Now()
				time.Sleep(writeTime)
				return make([]error, len(records))
			}}
		go func() { defer close(q.done); q.run(ctx) }()
		t.Cleanup(func() { cancel(); q.Close(context.Background()) })
		for range 2 * MaxOptionalBatch {
			if !q.Enqueue(optionalFixture()) {
				t.Fatal("受付失敗")
			}
		}
		synctest.Wait()
		first := <-starts
		time.Sleep(writeTime)
		synctest.Wait()
		time.Sleep(optionalBatchInterval - time.Nanosecond)
		synctest.Wait()
		if len(starts) != 0 {
			t.Fatal("開始時刻から数え、遅い保存後の間隔を失った")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if second := <-starts; second.Sub(first) != writeTime+optionalBatchInterval {
			t.Fatal(second.Sub(first))
		}
		if err := q.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if status := q.Status(); status.Saved != 128 || status.Pending != 0 {
			t.Fatal(status)
		}
	})
}
