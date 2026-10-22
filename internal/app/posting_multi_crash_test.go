// 共有proposal/decisionと独立WALの途中でプロセスを強制終了し、各threadを照合復旧する。
package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPostingMultiBatchProcessCrash(t *testing.T) {
	owner, create, now := postingFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, ed25519.SeedSize))
	open := func(root string) ([]*PostingLog, *evidence.Journal) {
		t.Helper()
		j, err := evidence.OpenJournal(filepath.Join(root, "20231114"), owner, 20231114, 10, key, PostingValidator(fixtureCapture))
		if err != nil {
			t.Fatal(err)
		}
		var logs []*PostingLog
		for index := range 2 {
			p, err := OpenPosting(filepath.Join(root, "threads"), owner, 1700000000+uint64(index), []*evidence.Journal{j}, j, now)
			if err != nil {
				t.Fatal(err)
			}
			logs = append(logs, p)
		}
		return logs, j
	}
	if stage := os.Getenv("OIMO_MULTI_CRASH_STAGE"); stage != "" {
		logs, j := open(os.Getenv("OIMO_MULTI_CRASH_ROOT"))
		defer j.Close()
		for _, p := range logs {
			defer p.Close()
		}
		capture := []byte(`{"fixture":true}`)
		for _, p := range logs {
			f, _, err := postingFrame(create)
			if err != nil {
				t.Fatal(err)
			}
			f.Records[0].ID = domain.NewID()
			raw, err := store.EncodeFrame(f)
			if err != nil {
				t.Fatal(err)
			}
			if result := p.Post(context.Background(), raw, capture, now); result.Status != store.Durable {
				t.Fatal(result)
			}
		}
		batch := &PostingBatch{}
		for seq := uint32(2); seq <= 5; seq++ {
			for _, p := range logs {
				if result := batch.Stage(context.Background(), p, batchReply(t, create, seq), capture, now); !errors.Is(result.Err, ErrPostingPrepared) {
					t.Fatal(result)
				}
			}
		}
		logs[0].checkpoint = func(at string) error {
			if stage == "partial-threads" && at == "proposal" {
				var first, second [][]byte
				for _, pending := range batch.posts {
					if pending.p == logs[0] {
						first = append(first, pending.frame)
					} else {
						second = append(second, pending.frame)
					}
				}
				if result := logs[0].thread.AppendBatch(first); result.Status != store.Durable {
					t.Fatal(result)
				}
				file, err := os.OpenFile(filepath.Join(logs[1].parent, "1700000001", "delta-000001.wal"), os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					return err
				}
				for _, frame := range second[:2] {
					if _, err = file.Write(frame); err != nil {
						return err
					}
				}
				if err = file.Sync(); err != nil {
					return err
				}
				if _, err = file.Write(second[2][:len(second[2])/2]); err != nil {
					return err
				}
				return syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
			if at == stage {
				return syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
			return nil
		}
		batch.Commit()
		t.Fatal("強制終了の境界へ到達しなかった")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"proposal", "partial-threads", "thread", "decision"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "threads"), 0700); err != nil {
				t.Fatal(err)
			}
			child := exec.Command(executable, "-test.run=^TestPostingMultiBatchProcessCrash$")
			child.Env = append(os.Environ(), "OIMO_MULTI_CRASH_STAGE="+stage, "OIMO_MULTI_CRASH_ROOT="+root)
			out, err := child.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) {
				t.Fatalf("SIGKILLで終了しなかった: %v %s", err, out)
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal(err, string(out))
			}
			logs, j := open(root)
			defer j.Close()
			for index, p := range logs {
				defer p.Close()
				want := uint32(5)
				if stage == "proposal" {
					want = 1
				}
				if stage == "partial-threads" && index == 1 {
					want = 3
				}
				if p.Snapshot(now).PostCount != want {
					t.Fatal("独立WALの復旧件数", index, p.Snapshot(now).PostCount, want)
				}
				for _, entry := range p.proposals {
					if entry.payload.ThreadSeq > domain.U64(want) {
						continue
					}
					raw, err := entry.decodeFrame()
					if err != nil {
						t.Fatal(err)
					}
					if result := p.Post(context.Background(), raw, []byte(`{"fixture":true}`), now); result.Status != store.Durable || !result.Duplicate {
						t.Fatal("復旧後の再送", result)
					}
				}
			}
		})
	}
}
