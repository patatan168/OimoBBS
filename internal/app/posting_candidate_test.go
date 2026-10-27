// CPU側の検証済み候補を、元byte・元状態・所有スレッドが一致するときだけ適用する。
package app

import (
	"bytes"
	"errors"
	"oimobbs/internal/store"
	"testing"
)

func TestPreparedPostingRejectsChangedBytesStateAndOwner(t *testing.T) {
	for _, condition := range []string{"valid", "bytes", "state", "owner", "nil"} {
		t.Run(condition, func(t *testing.T) {
			p, j, create, now, _, _ := newPostingTest(t)
			capture := []byte(`{"fixture":true}`)
			if result := p.Post(t.Context(), create, capture, now); result.Status != store.Durable {
				t.Fatal(result)
			}
			raw := batchReply(t, create, 2)
			f, op, err := postingFrame(raw)
			if err != nil {
				t.Fatal(err)
			}
			previous := p.postingState()
			next, err := store.ValidateThreadFrame(previous, raw)
			if err != nil {
				t.Fatal(err)
			}
			rate, err := parsedFrameRateRecord(f, op)
			if err != nil {
				t.Fatal(err)
			}
			_, previousHash, _ := p.postingSourceIdentity()
			candidate := &PreparedPosting{thread: p.thread, previousHash: previousHash, log: p, previous: previous, next: next, raw: raw, frame: f, op: op, rate: rate}
			borrowed := candidate.Frame()
			if !bytes.Equal(borrowed, raw) {
				t.Fatal("frame changed")
			}
			switch condition {
			case "bytes":
				borrowed[len(borrowed)-1] ^= 1
			case "state":
				copyState := *previous
				copyState.Revision++
				candidate.previous = &copyState
			case "owner":
				candidate.log = &PostingLog{}
			case "nil":
				candidate = nil
			}
			before := j.CommitStats()
			batch := &PostingBatch{}
			result := batch.StagePrepared(t.Context(), p, borrowed, capture, now, candidate)
			if condition == "valid" {
				if !errors.Is(result.Err, ErrPostingPrepared) || p.SharedSnapshot(now).PostCount != 1 {
					t.Fatal("premature publication", result)
				}
				if saved := batch.Commit(); saved.Status != store.Durable {
					t.Fatal(saved)
				}
				if p.SharedSnapshot(now).PostCount != 2 {
					t.Fatal("missing prepared reply")
				}
			} else if result.Status != store.NotWritten || result.Err == nil || j.CommitStats() != before || batch.Count() != 0 {
				t.Fatal("invalid candidate accepted", result)
			}
		})
	}
}

func TestPreparedPostingSurvivesEquivalentDurableBoundary(t *testing.T) {
	p, _, create, now, _, _ := newPostingTest(t)
	capture := []byte(`{"fixture":true}`)
	if result := p.Post(t.Context(), create, capture, now); result.Status != store.Durable {
		t.Fatal(result)
	}
	first := &PostingBatch{}
	if result := first.Stage(t.Context(), p, batchReply(t, create, 2), capture, now); !errors.Is(result.Err, ErrPostingPrepared) {
		t.Fatal(result)
	}
	old := p.postingState()
	raw := batchReply(t, create, 3)
	f, op, err := postingFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	next, err := store.ValidateThreadFrame(old, raw)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := parsedFrameRateRecord(f, op)
	if err != nil {
		t.Fatal(err)
	}
	_, previousHash, _ := p.postingSourceIdentity()
	candidate := &PreparedPosting{thread: p.thread, previousHash: previousHash, log: p, previous: old, next: next, raw: raw, frame: f, op: op, rate: rate}
	if result := first.Commit(); result.Status != store.Durable {
		t.Fatal(result)
	}
	if p.postingState() == old {
		t.Fatal("test needs a distinct canonical replay state")
	}
	second := &PostingBatch{}
	result := second.StagePrepared(t.Context(), p, candidate.Frame(), capture, now, candidate)
	if !errors.Is(result.Err, ErrPostingPrepared) {
		t.Fatal("equivalent durable state rejected", result)
	}
	if result := second.Commit(); result.Status != store.Durable {
		t.Fatal(result)
	}
	if p.SharedSnapshot(now).PostCount != 3 {
		t.Fatal("missing boundary reply")
	}
}

func TestPreparedPostingRejectsSameRevisionDifferentBranch(t *testing.T) {
	p, j, create, now, _, _ := newPostingTest(t)
	capture := []byte(`{"fixture":true}`)
	if result := p.Post(t.Context(), create, capture, now); result.Status != store.Durable {
		t.Fatal(result)
	}
	first := &PostingBatch{}
	if result := first.Stage(t.Context(), p, batchReply(t, create, 2), capture, now); !errors.Is(result.Err, ErrPostingPrepared) {
		t.Fatal(result)
	}
	previous := p.postingState()
	_, hash, _ := p.postingSourceIdentity()
	raw := batchReply(t, create, 3)
	f, op, err := postingFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	next, err := store.ValidateThreadFrame(previous, raw)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := parsedFrameRateRecord(f, op)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &PreparedPosting{thread: p.thread, previousHash: hash, log: p, previous: previous, next: next, raw: raw, frame: f, op: op, rate: rate}
	first.Discard()
	second := &PostingBatch{}
	defer second.Discard()
	if result := second.Stage(t.Context(), p, batchReply(t, create, 2), capture, now); !errors.Is(result.Err, ErrPostingPrepared) {
		t.Fatal(result)
	}
	before := j.CommitStats()
	result := second.StagePrepared(t.Context(), p, candidate.Frame(), capture, now, candidate)
	if result.Status != store.NotWritten || result.Err == nil || second.Count() != 1 || j.CommitStats() != before {
		t.Fatal("old branch candidate accepted", result)
	}
}
