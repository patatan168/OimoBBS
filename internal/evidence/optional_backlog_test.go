// 非必須ログの集中到着で保存待機を解除し、滞留解消後にI/Oの間隔を戻すことを検査する。
package evidence

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

func TestOptionalPressureIncludesInflightAndSignalsWriter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		first := true
		q, err := NewOptionalBatchQueue(func(_ context.Context, records []OptionalRecord) []error {
			if first {
				first = false
				close(started)
				<-release
			}
			return make([]error, len(records))
		})
		if err != nil {
			t.Fatal(err)
		}
		if !q.Enqueue(optionalFixture()) {
			t.Fatal("最初の受付失敗")
		}
		<-started
		if q.BacklogPressure() {
			t.Fatal("通常量で逼迫扱い")
		}
		for range 4*MaxOptionalBatch - 1 {
			if !q.Enqueue(optionalFixture()) {
				t.Fatal("逼迫通知前に欠測")
			}
		}
		if !q.BacklogPressure() {
			t.Fatal("保存中の一行を予約から除外した")
		}
		select {
		case <-q.BacklogSignal():
		default:
			t.Fatal("保存workerへ逼迫を通知しなかった")
		}
		close(release)
		if err := q.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if q.BacklogPressure() || q.Status().Saved != 4*MaxOptionalBatch {
			t.Fatal(q.Status())
		}
	})
}

func TestOptionalBatchBacklogWakesPacingAndRestoresInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		starts := make(chan time.Time, 8)
		q, err := NewOptionalBatchQueue(func(_ context.Context, records []OptionalRecord) []error {
			starts <- time.Now()
			return make([]error, len(records))
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { q.Close(context.Background()) })
		for range MaxOptionalBatch {
			if !q.Enqueue(optionalFixture()) {
				t.Fatal("最初の保存を受け付けなかった")
			}
		}
		synctest.Wait()
		first := <-starts
		if !q.Enqueue(optionalFixture()) {
			t.Fatal("待機開始の記録を受け付けなかった")
		}
		synctest.Wait()
		if len(starts) != 0 {
			t.Fatal("低密度の到着で保存間隔を省いた")
		}
		// 受付上限1024件の手前で保存を再開し、列が満ちる前に集中到着へ追従する。
		for range 4*MaxOptionalBatch - 1 {
			if !q.Enqueue(optionalFixture()) {
				t.Fatal("受付上限より前に欠測した")
			}
		}
		synctest.Wait()
		if len(starts) != 1 {
			t.Fatal("滞留が増えても待機を解除しなかった", q.Status())
		}
		second := <-starts
		if !second.Equal(first) || q.Status().Saved != 2*MaxOptionalBatch {
			t.Fatal("集中到着で不要な保存間隔を待った", second.Sub(first), q.Status())
		}
		time.Sleep(optionalBatchInterval)
		synctest.Wait()
		if len(starts) != 1 || (<-starts).Sub(second) != optionalBatchInterval {
			t.Fatal("滞留が減った後に保存間隔を戻さなかった")
		}
		if err := q.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		status := q.Status()
		if status.Accepted != 5*MaxOptionalBatch || status.Saved != status.Accepted || status.Pending != 0 || status.Failed != 0 || status.DroppedCapacity != 0 {
			t.Fatal(status)
		}
	})
}
