// 一括投稿の中間候補を公開せず、不正な後続frameが最新候補を壊さないことを確認する。
package app

import (
	"context"
	"errors"
	"oimobbs/internal/store"
	"runtime"
	"testing"
)

// TestPostingBatchCandidateLifetime は破棄・失敗・確定を経ても公開済みsnapshotを保つ。
func TestPostingBatchCandidateLifetime(t *testing.T) {
	p, _, create, now, _, _ := newPostingTest(t)
	capture := []byte(`{"fixture":true}`)
	if result := p.Post(context.Background(), create, capture, now); result.Status != store.Durable {
		t.Fatal(result)
	}
	for start := uint32(2); start < 130; start += store.MaxCommitFrames {
		batch := &PostingBatch{}
		for seq := start; seq < start+store.MaxCommitFrames; seq++ {
			if result := batch.Stage(context.Background(), p, batchReply(t, create, seq), capture, now); !errors.Is(result.Err, ErrPostingPrepared) {
				t.Fatal(result)
			}
		}
		if result := batch.Commit(); result.Status != store.Durable {
			t.Fatal(result)
		}
	}
	public := p.SharedSnapshot(now)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	batch := &PostingBatch{}
	for seq := uint32(130); seq < 130+store.MaxCommitFrames; seq++ {
		if result := batch.Stage(context.Background(), p, batchReply(t, create, seq), capture, now); !errors.Is(result.Err, ErrPostingPrepared) {
			t.Fatal(result)
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("retained candidate heap delta: %d bytes", int64(after.HeapAlloc)-int64(before.HeapAlloc))
	if p.SharedSnapshot(now).PostCount != 129 || public.PostCount != 129 {
		t.Fatal("staged posts published")
	}
	batch.Discard()
	if p.SharedSnapshot(now).PostCount != 129 {
		t.Fatal("discard changed publication")
	}
	batch = &PostingBatch{}
	frame := batchReply(t, create, 130)
	if result := batch.Stage(context.Background(), p, frame, capture, now); !errors.Is(result.Err, ErrPostingPrepared) {
		t.Fatal(result)
	}
	// 連番を飛ばした操作は拒否し、次の正しい連番を受け付ける。
	if result := batch.Stage(context.Background(), p, batchReply(t, create, 132), capture, now); result.Status != store.NotWritten || errors.Is(result.Err, ErrPostingPrepared) {
		t.Fatal("invalid successor changed candidate", result)
	}
	if result := batch.Stage(context.Background(), p, batchReply(t, create, 131), capture, now); !errors.Is(result.Err, ErrPostingPrepared) {
		t.Fatal(result)
	}
	if result := batch.Commit(); result.Status != store.Durable {
		t.Fatal(result)
	}
	if p.SharedSnapshot(now).PostCount != 131 || public.PostCount != 129 {
		t.Fatal("committed count or previous publication changed")
	}
}
