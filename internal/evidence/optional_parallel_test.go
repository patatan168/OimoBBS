// 非必須ログの並行計算でも、全検査の成功前にはSyncも確定履歴も更新しないことを検査する。
package evidence

import (
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestOptionalParallelValidationJoinsBeforePersistence(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "durable", true: "rejected"}[reject], func(t *testing.T) {
			j, _, _, _ := optionalJournalFixture(t)
			defer j.Close()
			record := optionalFixture()
			j.validate = func(string, []byte) error { return nil }
			if _, r := j.Append(record.ID, "attempt", record.Finished, func(src Source) ([]byte, error) {
				return json.Marshal(OptionalPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), record})
			}); r.Status != store.Durable {
				t.Fatal(r)
			}
			records := make([]OptionalRecord, 8)
			for i := range records {
				records[i] = record
				records[i].ID = domain.NewID()
			}
			before := j.CommitStats()
			seq := j.seq
			entered, release := make(chan struct{}, 4), make(chan struct{})
			var calls atomic.Int32
			rejected := errors.New("rejected optional payload")
			j.validate = func(_ string, raw []byte) error {
				if calls.Add(1) <= 4 {
					entered <- struct{}{}
					<-release
				}
				var p OptionalPayload
				if err := json.Unmarshal(raw, &p); err != nil {
					return err
				}
				if reject && p.Record.ID == records[3].ID {
					return rejected
				}
				return nil
			}
			done := make(chan store.CommitResult, 1)
			go func() { done <- j.appendOptionalBatch(records, func(int64, int64) error { return nil }) }()
			for range 4 {
				<-entered
			}
			if j.CommitStats() != before || j.seq != seq {
				t.Error("published before validators joined")
			}
			close(release)
			result := <-done
			if calls.Load() != 8 || j.preparedPayloads != nil {
				t.Fatal("worker lifetime", calls.Load())
			}
			if reject {
				if result.Status != store.NotWritten || !errors.Is(result.Err, rejected) || j.CommitStats() != before || j.seq != seq {
					t.Fatal("invalid batch reached storage", result)
				}
			} else if result.Status != store.Durable || j.seq != seq+8 || j.CommitStats().Syncs-before.Syncs != 1 {
				t.Fatal(result)
			}
		})
	}
}
