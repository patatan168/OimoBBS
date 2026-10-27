// 一括返信の非公開候補、各耐久境界の停止、取消と再起動後の再送を検査する。
package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPostingBatchProcessCrash(t *testing.T) {
	owner, create, now := postingFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, ed25519.SeedSize))
	open := func(root string) (*PostingLog, *evidence.Journal) {
		t.Helper()
		j, e := evidence.OpenJournal(filepath.Join(root, "20231114"), owner, 20231114, 10, key, PostingValidator(fixtureCapture))
		if e != nil {
			t.Fatal(e)
		}
		p, e := OpenPosting(filepath.Join(root, "threads"), owner, 1700000000, []*evidence.Journal{j}, j, now)
		if e != nil {
			t.Fatal(e)
		}
		return p, j
	}
	if stage := os.Getenv("OIMO_BATCH_CRASH_STAGE"); stage != "" {
		p, j := open(os.Getenv("OIMO_BATCH_CRASH_ROOT"))
		defer p.Close()
		defer j.Close()
		if r := p.Post(context.Background(), create, []byte(`{"fixture":true}`), now); r.Status != store.Durable {
			t.Fatal(r)
		}
		batch := &PostingBatch{}
		for seq := uint32(2); seq <= 5; seq++ {
			if r := batch.Stage(context.Background(), p, batchReply(t, create, seq), []byte(`{"fixture":true}`), now); !errors.Is(r.Err, ErrPostingPrepared) {
				t.Fatal(r)
			}
		}
		p.checkpoint = func(at string) error {
			if stage == "partial-thread" && at == "proposal" {
				f, e := os.OpenFile(filepath.Join(p.parent, "1700000000", "delta-000001.wal"), os.O_WRONLY|os.O_APPEND, 0600)
				if e != nil {
					return e
				}
				for _, pending := range batch.posts[:2] {
					if _, e = f.Write(pending.frame); e != nil {
						return e
					}
				}
				if e = f.Sync(); e != nil {
					return e
				}
				if _, e = f.Write(batch.posts[2].frame[:len(batch.posts[2].frame)/2]); e != nil {
					return e
				}
				return syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
			if at == stage {
				return syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
			return nil
		}
		batch.Commit()
		t.Fatal("crash checkpoint not reached")
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, stage := range []string{"proposal", "partial-thread", "thread", "decision"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(filepath.Join(root, "threads"), 0700); e != nil {
				t.Fatal(e)
			}
			child := exec.Command(executable, "-test.run=^TestPostingBatchProcessCrash$")
			child.Env = append(os.Environ(), "OIMO_BATCH_CRASH_STAGE="+stage, "OIMO_BATCH_CRASH_ROOT="+root)
			out, e := child.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(e, &exited) {
				t.Fatalf("expected SIGKILL: %v %s", e, out)
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal(e)
			}
			p, j := open(root)
			defer p.Close()
			defer j.Close()
			want := uint32(5)
			if stage == "proposal" {
				want = 1
			}
			if stage == "partial-thread" {
				want = 3
			}
			if p.Snapshot(now).PostCount != want {
				t.Fatal(p.Snapshot(now).PostCount, want)
			}
			if want > 1 {
				for _, entry := range p.proposals {
					if entry.payload.ThreadSeq > domain.U64(want) {
						continue
					}
					frame, e := entry.decodeFrame()
					if e != nil {
						t.Fatal(e)
					}
					if r := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); r.Status != store.Durable || !r.Duplicate {
						t.Fatal(r)
					}
				}
			}
		})
	}
}

func batchReply(t *testing.T, create []byte, seq uint32) []byte {
	t.Helper()
	f, op, e := postingFrame(replyFixture(t, create))
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
	op.Dedup.Request[1] = byte(seq)
	(*op.Dedup.RequestID)[1] = byte(seq)
	payload.Posts[0].Number = seq
	op.Payload, _ = json.Marshal(payload)
	f.FirstSeq = uint64(seq)
	f.Records[0].JSON, _ = json.Marshal(op)
	frame, e := store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	return frame
}

func TestPostingBatchDurabilityAndRecovery(t *testing.T) {
	for _, stop := range []string{"", "proposal", "thread", "decision"} {
		t.Run(stop, func(t *testing.T) {
			p, j, create, now, root, key := newPostingTest(t)
			capture := []byte(`{"fixture":true}`)
			if r := p.Post(context.Background(), create, capture, now); r.Status != store.Durable {
				t.Fatal(r)
			}
			reader := p.PublicReader()
			beforeThread, beforeJournal := p.thread.CommitStats(), j.CommitStats()
			old, _ := reader.Snapshot(now)
			batch := &PostingBatch{}
			var replies [][]byte
			for seq := uint32(2); seq <= 5; seq++ {
				frame := batchReply(t, create, seq)
				replies = append(replies, frame)
				result := batch.Stage(context.Background(), p, frame, capture, now)
				if result.PostNumber != seq || !errors.Is(result.Err, ErrPostingPrepared) {
					t.Fatal(result)
				}
				public, status := reader.Snapshot(now)
				if status != 200 || public.PostCount != 1 || old.PostCount != 1 {
					t.Fatal("prepared reply became public")
				}
			}
			stages := []string{}
			p.checkpoint = func(stage string) error {
				stages = append(stages, stage)
				if stage == stop {
					return errors.New("injected stop")
				}
				return nil
			}
			r := batch.Commit()
			if stop == "" {
				if r.Status != store.Durable || len(stages) != 3 || p.Snapshot(now).PostCount != 5 {
					t.Fatal(r, stages)
				}
				thread, journal := p.thread.CommitStats(), j.CommitStats()
				if thread.Syncs-beforeThread.Syncs != 1 || journal.Syncs-beforeJournal.Syncs != 2 || thread.Writes-beforeThread.Writes != 1 || journal.Writes-beforeJournal.Writes != 2 {
					t.Fatal("batch did not reduce WAL calls", thread, journal)
				}
			} else if r.Status != store.Unknown {
				t.Fatal(r)
			}
			owner := p.owner
			_ = p.Close()
			_ = j.Close()
			j, e := evidence.OpenJournal(filepath.Join(root, "20231114"), owner, 20231114, 10, key, PostingValidator(fixtureCapture))
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			p, e = OpenPosting(filepath.Join(root, "threads"), owner, 1700000000, []*evidence.Journal{j}, j, now)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			want := uint32(5)
			if stop == "proposal" {
				want = 1
			}
			if p.Snapshot(now).PostCount != want {
				t.Fatal("wrong recovered count", p.Snapshot(now).PostCount, want)
			}
			if want == 5 {
				for _, reply := range replies {
					if r := p.Post(context.Background(), reply, capture, now); r.Status != store.Durable || !r.Duplicate {
						t.Fatal(r)
					}
				}
			}
		})
	}
}

func TestPostingBatchCancellationAndDuplicate(t *testing.T) {
	for _, when := range []string{"before", "after-proposal"} {
		t.Run(when, func(t *testing.T) {
			p, j, create, now, _, _ := newPostingTest(t)
			capture := []byte(`{"fixture":true}`)
			if r := p.Post(context.Background(), create, capture, now); r.Status != store.Durable {
				t.Fatal(r)
			}
			before := len(j.Entries())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			batch := &PostingBatch{}
			frame := batchReply(t, create, 2)
			if r := batch.Stage(ctx, p, frame, capture, now); !errors.Is(r.Err, ErrPostingPrepared) {
				t.Fatal(r)
			}
			if r, ok := p.Retry(func() *domain.Dedup { _, op, _ := postingFrame(frame); return op.Dedup }(), now); !ok || !r.Duplicate || !errors.Is(r.Err, ErrPostingPrepared) {
				t.Fatal(r, ok)
			}
			if when == "before" {
				cancel()
			} else {
				p.checkpoint = func(stage string) error {
					if stage == "proposal" {
						cancel()
					}
					return nil
				}
			}
			r := batch.Commit()
			if when == "before" {
				if r.Status != store.NotWritten || !errors.Is(r.Err, context.Canceled) || len(j.Entries()) != before || p.Snapshot(now).PostCount != 1 || p.batch != nil {
					t.Fatal(r)
				}
			} else if r.Status != store.Durable || p.Snapshot(now).PostCount != 2 {
				t.Fatal(r)
			}
		})
	}
}

func TestPostingBatchSyncReduction(t *testing.T) {
	for _, groupSize := range []uint32{1, 16, store.MaxCommitFrames} {
		t.Run(fmt.Sprint(groupSize), func(t *testing.T) {
			p, j, create, now, _, _ := newPostingTest(t)
			capture := []byte(`{"fixture":true}`)
			if r := p.Post(context.Background(), create, capture, now); r.Status != store.Durable {
				t.Fatal(r)
			}
			threadBefore, journalBefore := p.thread.CommitStats(), j.CommitStats()
			batch := &PostingBatch{}
			for seq := uint32(2); seq <= store.MaxCommitFrames+1; seq++ {
				frame := batchReply(t, create, seq)
				if r := batch.Stage(context.Background(), p, frame, capture, now); !errors.Is(r.Err, ErrPostingPrepared) {
					t.Fatal(r)
				}
				if groupSize == store.MaxCommitFrames && seq == store.MaxCommitFrames+1 {
					before := j.CommitStats()
					if batch.Fits(p, frame, capture) {
						t.Fatal("batch count limit exceeded")
					}
					if r := batch.Stage(context.Background(), p, batchReply(t, create, seq+1), capture, now); r.Status != store.NotWritten || !errors.Is(r.Err, store.ErrCorrupt) || j.CommitStats() != before {
						t.Fatal("overflow started storage", r)
					}
				}
				if (seq-1)%groupSize == 0 {
					if r := batch.Commit(); r.Status != store.Durable {
						t.Fatal(r)
					}
					batch = &PostingBatch{}
				}
			}
			threadAfter, journalAfter := p.thread.CommitStats(), j.CommitStats()
			syncs := threadAfter.Syncs - threadBefore.Syncs + journalAfter.Syncs - journalBefore.Syncs
			writes := threadAfter.Writes - threadBefore.Writes + journalAfter.Writes - journalBefore.Writes
			want := uint64(3 * store.MaxCommitFrames / groupSize)
			if syncs != want || writes != want || p.Snapshot(now).PostCount != store.MaxCommitFrames+1 {
				t.Fatal(syncs, writes, want)
			}
			t.Logf("64 replies group=%d: WAL Write=%d Sync=%d bytes=%d", groupSize, writes, syncs, threadAfter.Bytes-threadBefore.Bytes+journalAfter.Bytes-journalBefore.Bytes)
		})
	}
}
