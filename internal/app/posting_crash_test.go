// 子プロセスをWrite/Sync境界でSIGKILLし、closeされないfileからの一体復旧を検査する。
package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPostingProcessCrash(t *testing.T) {
	owner, frame, now := postingFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize))
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
	if stage := os.Getenv("OIMO_POST_CRASH_STAGE"); stage != "" {
		p, j := open(os.Getenv("OIMO_POST_CRASH_ROOT"))
		defer p.Close()
		defer j.Close()
		p.checkpoint = func(at string) error {
			if stage == "creation_wal" && at == "proposal" {
				// current設置前のWALをWriteした直後に強制終了する。Close/Syncは行わない。
				dir := filepath.Join(p.parent, "1700000000")
				if e := os.Mkdir(dir, 0700); e != nil {
					return e
				}
				header, e := store.EncodeHeader(store.Header{Owner: owner, Key: p.key, Generation: 1})
				if e != nil {
					return e
				}
				f, e := os.OpenFile(filepath.Join(dir, "delta-000001.wal"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					return e
				}
				block, e := store.EncodeWALBlock([][]byte{frame})
				if e != nil {
					return e
				}
				if _, e = f.Write(append(header, block...)); e != nil {
					return e
				}
			}
			if at == stage || stage == "creation_wal" && at == "proposal" {
				if e := syscall.Kill(os.Getpid(), syscall.SIGKILL); e != nil {
					return e
				}
			}
			return nil
		}
		p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now)
		t.Fatal("crash checkpoint not reached")
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, stage := range []string{"proposal", "creation_wal", "thread", "decision"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(filepath.Join(root, "threads"), 0700); e != nil {
				t.Fatal(e)
			}
			child := exec.Command(executable, "-test.run=^TestPostingProcessCrash$")
			child.Env = append(os.Environ(), "OIMO_POST_CRASH_STAGE="+stage, "OIMO_POST_CRASH_ROOT="+root)
			out, e := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatalf("expected SIGKILL: %v %s", e, out)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("unexpected exit: %v %s", e, out)
			}
			p, j := open(root)
			defer p.Close()
			defer j.Close()
			if stage == "proposal" {
				if p.Snapshot(now) != nil || len(j.Entries()) != 2 {
					t.Fatal("unaccepted proposal published")
				}
				return
			}
			if p.Snapshot(now) == nil || p.Snapshot(now).PostCount != 1 {
				t.Fatal("durable post lost")
			}
			if r := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); r.Status != store.Durable || !r.Duplicate {
				t.Fatal(r)
			}
		})
	}
}
