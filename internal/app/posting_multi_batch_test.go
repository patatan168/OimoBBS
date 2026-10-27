// 複数スレッドの署名同期共有が、取消・途中停止・非公開候補・個別復旧を保つことを検査する。
package app

import (
	"context"
	"errors"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"testing"
)

// 共有WALでは三境界の実Sync差分だけを返し、準備・以前の投稿の待ちを持ち越さない。
func TestPostingBatchSharedSyncDuration(t *testing.T) {
	p, journal, create, now, _, _ := newPostingTest(t)
	capture := []byte(`{"fixture":true}`)
	if result := p.Post(t.Context(), create, capture, now); result.Status != store.Durable {
		t.Fatal(result)
	}
	group := store.NewThreadCommitGroup(p.parent, p.owner)
	defer group.Close()
	for seq := uint32(2); seq <= 3; seq++ {
		batch := &PostingBatch{CommitGroup: group}
		if result := batch.Stage(t.Context(), p, batchReply(t, create, seq), capture, now); !errors.Is(result.Err, ErrPostingPrepared) {
			t.Fatal(result)
		}
		beforeJournal, beforeGroup := journal.CommitStats(), group.Stats()
		if result := batch.Commit(); result.Status != store.Durable {
			t.Fatal(result)
		}
		want := journal.CommitStats().SyncDuration - beforeJournal.SyncDuration + group.Stats().SyncDuration - beforeGroup.SyncDuration
		if batch.SyncDuration() <= 0 || batch.SyncDuration() != want || group.Stats().Syncs-beforeGroup.Syncs != 1 {
			t.Fatal("共有同期の差分", batch.SyncDuration(), want)
		}
	}
}

func TestPostingBatchAcrossThreads(t *testing.T) {
	for _, stop := range []string{"", "cancel", "proposal", "partial-thread", "first-thread", "thread", "decision"} {
		t.Run(stop, func(t *testing.T) {
			first, journal, create, now, root, signingKey := newPostingTest(t)
			capture := []byte(`{"fixture":true}`)
			if r := first.Post(context.Background(), create, capture, now); r.Status != store.Durable {
				t.Fatal(r)
			}
			second, err := OpenPosting(first.parent, first.owner, first.key+1, []*evidence.Journal{journal}, journal, now)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			f, _, err := postingFrame(create)
			if err != nil {
				t.Fatal(err)
			}
			f.Records[0].ID = domain.NewID()
			otherCreate, err := store.EncodeFrame(f)
			if err != nil {
				t.Fatal(err)
			}
			if r := second.Post(context.Background(), otherCreate, capture, now); r.Status != store.Durable {
				t.Fatal(r)
			}
			beforeJournal := journal.CommitStats()
			beforeFirst, beforeSecond := first.thread.CommitStats(), second.thread.CommitStats()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			batch := &PostingBatch{}
			for seq := uint32(2); seq <= 3; seq++ {
				for _, p := range []*PostingLog{first, second} {
					frame := batchReply(t, create, seq)
					if r := batch.Stage(ctx, p, frame, capture, now); !errors.Is(r.Err, ErrPostingPrepared) {
						t.Fatal(r)
					}
				}
			}
			for _, p := range []*PostingLog{first, second} {
				p.checkpoint = func(stage string) error {
					if first.Snapshot(now).PostCount != 1 || second.Snapshot(now).PostCount != 1 {
						t.Fatal("全決定の同期前に候補を公開した")
					}
					if stop == "partial-thread" && p == first && stage == "proposal" {
						var frames [][]byte
						for _, pending := range batch.posts {
							if pending.p == first {
								frames = append(frames, pending.frame)
							}
						}
						if saved := p.thread.AppendBatch(frames); saved.Status != store.Durable {
							t.Fatal(saved)
						}
						return errors.New("only one thread reached storage")
					}
					if stop == stage && p == second || stop == "first-thread" && p == first && stage == "thread" {
						return errors.New("injected multi-thread stop")
					}
					return nil
				}
			}
			if stop == "cancel" {
				cancel()
			}
			r := batch.Commit()
			switch stop {
			case "":
				if r.Status != store.Durable || first.Snapshot(now).PostCount != 3 || second.Snapshot(now).PostCount != 3 {
					t.Fatal(r)
				}
				if journal.CommitStats().Syncs-beforeJournal.Syncs != 2 || first.thread.CommitStats().Syncs-beforeFirst.Syncs != 1 || second.thread.CommitStats().Syncs-beforeSecond.Syncs != 1 {
					t.Fatal("共有署名journalの同期が投稿数に比例した")
				}
				want := journal.CommitStats().SyncDuration - beforeJournal.SyncDuration + max(first.thread.CommitStats().SyncDuration-beforeFirst.SyncDuration, second.thread.CommitStats().SyncDuration-beforeSecond.SyncDuration)
				if batch.SyncDuration() <= 0 || batch.SyncDuration() != want {
					t.Fatal("独立本文の同期時間を合算した", batch.SyncDuration(), want)
				}
			case "cancel":
				if r.Status != store.NotWritten || journal.CommitStats() != beforeJournal || first.batch != nil || second.batch != nil {
					t.Fatal("取消で保存または候補残存", r)
				}
				if batch.SyncDuration() != 0 {
					t.Fatal("取消を保存遅延として数えた")
				}
			default:
				if r.Status != store.Unknown {
					t.Fatal(r)
				}
				for _, p := range []*PostingLog{first, second} {
					if _, status := p.PublicReader().Snapshot(now); status != 503 {
						t.Fatal("結果不明の一部を公開した", status)
					}
				}
			}
			owner := first.owner
			_ = first.Close()
			_ = second.Close()
			_ = journal.Close()
			journal, err = evidence.OpenJournal(filepath.Join(root, "20231114"), owner, 20231114, 10, signingKey, PostingValidator(fixtureCapture))
			if err != nil {
				t.Fatal(err)
			}
			defer journal.Close()
			for index, expected := range []uint32{3, 3} {
				if stop == "proposal" || stop == "cancel" || stop == "partial-thread" && index == 1 {
					expected = 1
				}
				p, err := OpenPosting(filepath.Join(root, "threads"), owner, 1700000000+uint64(index), []*evidence.Journal{journal}, journal, now)
				if err != nil {
					t.Fatal(err)
				}
				if p.Snapshot(now).PostCount != expected {
					t.Fatal("復旧件数", index, p.Snapshot(now).PostCount, expected)
				}
				_ = p.Close()
			}
		})
	}
}

// 同期並列上限の前後でも、全スレッドの確定・取消・再起動照合を一つの耐久境界で保つ。
func TestPostingBatchManyIndependentThreads(t *testing.T) {
	for _, count := range []int{16, 17, 64} {
		for _, cancelled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/cancel=%t", count, cancelled), func(t *testing.T) {
				first, journal, create, now, root, signingKey := newPostingTest(t)
				capture := []byte(`{"fixture":true}`)
				var logs []*PostingLog
				for i := 0; i < count; i++ {
					p := first
					if i > 0 {
						var err error
						p, err = OpenPosting(first.parent, first.owner, first.key+uint64(i), []*evidence.Journal{journal}, journal, now)
						if err != nil {
							t.Fatal(err)
						}
					}
					logs = append(logs, p)
					t.Cleanup(func() { p.Close() })
					f, _, err := postingFrame(create)
					if err != nil {
						t.Fatal(err)
					}
					f.Records[0].ID = domain.NewID()
					raw, err := store.EncodeFrame(f)
					if err != nil {
						t.Fatal(err)
					}
					if r := p.Post(context.Background(), raw, capture, now); r.Status != store.Durable {
						t.Fatal(r)
					}
				}
				before := journal.CommitStats()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				batch := &PostingBatch{}
				for _, p := range logs {
					raw := batchReply(t, create, 2)
					r := batch.Stage(ctx, p, raw, capture, now)
					if !errors.Is(r.Err, ErrPostingPrepared) {
						t.Fatal(r)
					}
					_, op, err := postingFrame(raw)
					if err != nil {
						t.Fatal(err)
					}
					// 各スレッドで同じ再送キーを使っても、候補は自分の操作IDへ戻る。
					if retry, ok := p.Retry(op.Dedup, now); !ok || retry.OperationID != r.OperationID || !errors.Is(retry.Err, ErrPostingPrepared) {
						t.Fatal("pending retry crossed threads", retry, r, ok)
					}
				}
				if cancelled {
					cancel()
				}
				result := batch.Commit()
				want := uint32(2)
				if cancelled {
					want = 1
					if result.Status != store.NotWritten || journal.CommitStats() != before {
						t.Fatal("取消で保存を開始した", result)
					}
				} else if result.Status != store.Durable || journal.CommitStats().Syncs-before.Syncs != 2 {
					t.Fatal(result)
				}
				for _, p := range logs {
					if p.Snapshot(now).PostCount != want || p.thread.CommitStats().Syncs != uint64(want) || p.batch != nil {
						t.Fatal("独立WALの確定が不一致")
					}
					p.Close()
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := evidence.OpenJournal(filepath.Join(root, "20231114"), first.owner, 20231114, 10, signingKey, PostingValidator(fixtureCapture))
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				for _, previous := range logs {
					p, err := OpenPosting(first.parent, first.owner, previous.key, []*evidence.Journal{reopened}, reopened, now)
					if err != nil {
						t.Fatal(err)
					}
					if p.Snapshot(now).PostCount != want {
						t.Fatal("再起動時の採番不一致")
					}
					p.Close()
				}
			})
		}
	}
}
