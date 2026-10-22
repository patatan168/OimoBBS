// 投稿候補が一件分しか保持できない場合も、拒否せず分割確定してFIFOを維持する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
	"testing"
	"time"
)

func TestPostingBatchFlushesBeforeMemoryRetry(t *testing.T) {
	cfg, repo, info := postingRepositoryFixture(t)
	create := persistentFrame(t)
	first := repo.Post(t.Context(), info.ID, 0, create, []byte(`{"fixture":true}`))
	if first.Status != store.Durable {
		t.Fatal(first)
	}
	// 余裕16MiBと候補一件分の6MiB。次の候補は先行分を確定してから準備する。
	repo.memory.Store(&platform.MemoryState{Limit: 256 << 20, Headroom: 22 << 20})
	b := repo.posting[info.ID]
	p := b.threads[first.ThreadKey]
	attempts := make([]int, 6)
	completed := make([]bool, 6)
	value, err := b.worker.Submit(t.Context(), func() (any, error) {
		ops := make([]board.BatchOperation, 6)
		for index := range ops {
			ops[index] = board.BatchOperation{Context: context.Background(), Complete: func(value any, err error) {
				result, ok := value.(RepositoryPostingResult)
				if !ok || err != nil || result.Status != store.Durable || completed[index] {
					t.Error("stored completion duplicated or premature", index, value, err)
				}
				completed[index] = true
			}, Run: func() (any, error) {
				attempts[index]++
				if index > 0 && attempts[index] > 1 && !completed[index-1] {
					t.Error("earlier acknowledgement held behind uncommitted work")
				}
				now := time.Now()
				seq := p.SharedSnapshot(domain.Time(now.UnixNano())).PostCount + uint32(b.group.batch.Count()) + 1
				frame := persistentReply(t, create, now)
				f, _, err := store.ReadFrame(bytes.NewReader(frame))
				if err != nil {
					t.Fatal(err)
				}
				op, err := domain.ParseOperation(f.Records[0].JSON)
				if err != nil {
					t.Fatal(err)
				}
				var payload domain.Append
				if err = json.Unmarshal(op.Payload, &payload); err != nil {
					t.Fatal(err)
				}
				op.Revision = domain.U64(seq)
				op.After.PostCount, op.After.UserCount = seq, seq
				op.After.DATBytes = domain.U64(len(f.Records[0].DAT)) * domain.U64(seq)
				op.Dedup.PostNumber = seq
				op.Dedup.Request[1] = byte(index + 1)
				(*op.Dedup.RequestID)[1] = byte(index + 1)
				payload.Posts[0].Number = seq
				op.Payload, _ = json.Marshal(payload)
				f.FirstSeq = uint64(seq)
				f.Records[0].JSON, _ = json.Marshal(op)
				frame, err = store.EncodeFrame(f)
				if err != nil {
					t.Fatal(err)
				}
				return b.postAdmitted(first.ThreadKey, frame, []byte(`{"fixture":true}`)), nil
			}}
		}
		return b.runPostingBatch(ops), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, result := range value.([]board.BatchResult) {
		saved, ok := result.Value.(RepositoryPostingResult)
		if !ok || result.Err != nil || saved.Status != store.Durable || saved.PostNumber != uint32(index+2) {
			t.Fatal("split changed acceptance/order", index, result)
		}
		if index > 0 && attempts[index] != 2 {
			t.Fatal("candidate was not resumed exactly once", index, attempts)
		}
		if !completed[index] {
			t.Fatal("durable acknowledgement missing", index)
		}
	}
	snapshot, err := repo.Thread(t.Context(), info.ID, first.ThreadKey)
	if err != nil || snapshot.PostCount != 7 {
		t.Fatal("lost or duplicate reply", err, snapshot)
	}
	if repo.memoryReserved.Load() != 0 || repo.postReserved != 0 {
		t.Fatal("reservation leak", repo.memoryReserved.Load(), repo.postReserved)
	}
	for _, journal := range b.journals {
		if len(journal.Entries()) != 14 {
			t.Fatal("uncommitted candidate stored", len(journal.Entries()))
		}
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPostingRepository(cfg, postingCaptureFixture)
	if err != nil {
		t.Fatal("split batch replay", err)
	}
	defer reopened.Close()
	restored, err := reopened.Thread(t.Context(), info.ID, first.ThreadKey)
	if err != nil || restored.PostCount != 7 || !bytes.Equal(restored.DAT, snapshot.DAT) {
		t.Fatal("split changed durable DAT", err)
	}
}
