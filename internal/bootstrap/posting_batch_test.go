// 未保存グループの取消で候補を作り直し、有効な再送の採番と予約を保つことを検査する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"testing"
	"time"
)

func TestPostingBatchRebuildAfterCancellation(t *testing.T) { testPostingBatchRebuild(t, false, false) }

func TestPostingBatchRebuildAfterGuardChange(t *testing.T) { testPostingBatchRebuild(t, true, false) }

func TestPostingReadyBatchRebuildAfterCancellation(t *testing.T) {
	testPostingBatchRebuild(t, false, true)
}

func TestPostingReadyBatchRebuildAfterGuardChange(t *testing.T) {
	testPostingBatchRebuild(t, true, true)
}

func TestPostingBatchRebuildAfterParallelValidation(t *testing.T) {
	testPostingBatchRebuild(t, true, true, true)
}

func testPostingBatchRebuild(t *testing.T, guardChange, ready bool, validation ...bool) {
	t.Helper()
	guardUsed := false
	_, repo, info := postingRepositoryFixture(t)
	create := persistentFrame(t)
	first := repo.Post(context.Background(), info.ID, 0, create, []byte(`{"fixture":true}`))
	if first.Status != store.Durable {
		t.Fatal(first)
	}
	b := repo.posting[info.ID]
	p := b.threads[first.ThreadKey]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	value, e := b.worker.Submit(context.Background(), func() (any, error) {
		ops := make([]board.BatchOperation, 3)
		for i := range ops {
			currentCtx := context.Background()
			if i == 0 {
				currentCtx = ctx
			}
			ops[i] = board.BatchOperation{Context: currentCtx, Run: func() (any, error) {
				if e := currentCtx.Err(); e != nil {
					return nil, e
				}
				now := time.Now()
				seq := p.SharedSnapshot(domain.Time(now.UnixNano())).PostCount + uint32(b.group.batch.Count()) + 1
				frame := persistentReply(t, create, now)
				f, _, e := store.ReadFrame(bytes.NewReader(frame))
				if e != nil {
					t.Fatal(e)
				}
				op, e := domain.ParseOperation(f.Records[0].JSON)
				if e != nil {
					t.Fatal(e)
				}
				var payload domain.Append
				if e = json.Unmarshal(op.Payload, &payload); e != nil {
					t.Fatal(e)
				}
				op.Revision = domain.U64(seq)
				op.After.PostCount = seq
				op.After.UserCount = seq
				op.After.DATBytes = domain.U64(len(f.Records[0].DAT)) * domain.U64(seq)
				op.Dedup.PostNumber = seq
				request := byte(1)
				if i == 2 {
					request = 2
				}
				op.Dedup.Request[1] = request
				(*op.Dedup.RequestID)[1] = request
				payload.Posts[0].Number = seq
				op.Payload, _ = json.Marshal(payload)
				f.FirstSeq = uint64(seq)
				f.Records[0].JSON, _ = json.Marshal(op)
				frame, e = store.EncodeFrame(f)
				if e != nil {
					t.Fatal(e)
				}
				result := b.postAdmitted(first.ThreadKey, frame, []byte(`{"fixture":true}`))
				if i == 2 {
					if guardChange {
						if !guardUsed {
							if len(validation) > 0 && validation[0] {
								b.group.validations = append(b.group.validations, postingValidation{index: 0, check: func() error { return ErrCap }})
							} else {
								b.group.guards = append(b.group.guards, postingGuard{0, func() error { return ErrCap }})
							}
							guardUsed = true
						}
					} else {
						cancel()
					}
				}
				return result, nil
			}}
		}
		if ready {
			added := false
			return b.runPostingReadyBatch(ops[:2], func() []board.BatchOperation {
				if added {
					return nil
				}
				added = true
				return ops[2:]
			}), nil
		}
		return b.runPostingBatch(ops), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	results := value.([]board.BatchResult)
	wantError := error(context.Canceled)
	if guardChange {
		wantError = ErrCap
	}
	if !errors.Is(results[0].Err, wantError) {
		t.Fatal(results[0])
	}
	for i := 1; i < 3; i++ {
		result := results[i].Value.(RepositoryPostingResult)
		if result.Status != store.Durable || result.PostNumber != uint32(i+1) || results[i].Err != nil {
			t.Fatal(result, results[i].Err)
		}
	}
	snapshot, e := repo.Thread(context.Background(), info.ID, first.ThreadKey)
	if e != nil || snapshot.PostCount != 3 {
		t.Fatal(snapshot, e)
	}
	repo.packResourcesMu.Lock()
	reserved := repo.postReserved
	repo.packResourcesMu.Unlock()
	if reserved != 0 {
		t.Fatal("reservation leaked", reserved)
	}
	for _, journal := range b.journals {
		if len(journal.Entries()) != 6 {
			t.Fatal("cancelled candidates were stored", len(journal.Entries()))
		}
	}
}

// 確認だけの初期群で新しい保存群の64枠を消費せず、次の所有処理へ渡す。
func TestPostingReadyConfirmationPhaseDoesNotCollect(t *testing.T) {
	b := &postingBoard{}
	completed, collected := false, false
	operations := []board.BatchOperation{{Context: context.Background(), Run: func() (any, error) {
		return RepositoryPostingResult{CommitResult: store.CommitResult{Status: store.NotWritten}}, nil
	}, Complete: func(any, error) { completed = true }}}
	result := b.runPostingReadyBatch(operations, func() []board.BatchOperation { collected = true; return nil })
	if len(result) != 1 || !completed || collected {
		t.Fatal("確認群へ次の保存群を混ぜた", completed, collected)
	}
}
