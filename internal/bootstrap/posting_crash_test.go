// Repositoryでキー予約後と投稿確定後にSIGKILLし、サイト排他を再取得して再送する。
package bootstrap

import (
	"context"
	"encoding/json"
	"oimobbs/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRepositoryPostingCrash(t *testing.T) {
	if path := os.Getenv("OIMO_POSTING_REPO_CONFIG"); path != "" {
		cfg, e := LoadConfig(path)
		if e != nil {
			t.Fatal(e)
		}
		stage := os.Getenv("OIMO_POSTING_REPO_STAGE")
		repo, e := openPostingRepository(cfg, func(point string) {
			if point == stage {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
		}, postingCaptureFixture)
		if e != nil {
			t.Fatal(e)
		}
		boards, e := repo.Boards()
		if e != nil || len(boards) != 1 {
			t.Fatal(e)
		}
		frame, e := os.ReadFile(path + ".frame")
		if e != nil {
			t.Fatal(e)
		}
		result := repo.Post(context.Background(), boards[0].ID, 0, frame, []byte(`{"fixture":true}`))
		if result.Status != store.Durable {
			t.Fatal(result)
		}
		if stage == "accepted" {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		t.Fatal("checkpoint missed")
	}
	for _, stage := range []string{"reservation", "accepted"} {
		t.Run(stage, func(t *testing.T) {
			cfg, repo, b := postingRepositoryFixture(t)
			if e := repo.Close(); e != nil {
				t.Fatal(e)
			}
			frame := persistentFrame(t)
			raw, e := json.Marshal(cfg)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(filepath.Dir(cfg.DataDir), "posting-crash.json")
			mustWrite(t, path, raw)
			mustWrite(t, path+".frame", frame)
			child := exec.Command(os.Args[0], "-test.run=^TestRepositoryPostingCrash$")
			child.Env = append(os.Environ(), "OIMO_POSTING_REPO_CONFIG="+path, "OIMO_POSTING_REPO_STAGE="+stage)
			output, e := child.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok {
				t.Fatalf("not killed: %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("unexpected exit: %v %s", e, output)
			}
			repo, e = OpenPostingRepository(cfg, postingCaptureFixture)
			if e != nil {
				t.Fatal(e)
			}
			defer repo.Close()
			result := repo.Post(context.Background(), b.ID, 0, frame, []byte(`{"fixture":true}`))
			if result.Status != store.Durable || result.Duplicate != (stage == "accepted") {
				t.Fatal(result)
			}
			keys, e := postingNames(filepath.Join(cfg.DataDir, "boards", b.ID.String(), "threads"))
			if e != nil || len(keys) != 1 || keys[0] != result.ThreadKey {
				t.Fatal("duplicate thread", keys, e)
			}
		})
	}
}
