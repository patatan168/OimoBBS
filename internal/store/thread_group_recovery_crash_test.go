// 復旧の書込み・Sync・Closeで実プロセスをSIGKILLし、再実行元と進捗の再利用を確認する。
package store

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestThreadGroupRecoveryProcessProgress(t *testing.T) {
	if root := os.Getenv("OIMO_REPLAY_CRASH_ROOT"); root != "" {
		raw, err := os.ReadFile(filepath.Join(root, ThreadGroupFile))
		if err != nil {
			t.Fatal(err)
		}
		records, err := decodeThreadGroups(raw)
		if err != nil || len(records) == 0 {
			t.Fatal(err)
		}
		plans, err := prepareThreadGroupReplay(records, records[0].Owner, func(uint64, []byte) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		defer closeThreadGroupReplays(plans)
		stage := os.Getenv("OIMO_REPLAY_CRASH_STAGE")
		kill := func() {
			if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
		}
		for _, plan := range plans {
			if err = plan.open(root, records[0].Owner); err != nil {
				t.Fatal(err)
			}
			file := &replayFaultFile{threadReplayFile: plan.file}
			switch stage {
			case "write":
				file.afterWrite = kill
			case "sync":
				file.afterSync = kill
			case "close":
				file.afterClose = kill
			default:
				t.Fatal(stage)
			}
			plan.file = file
		}
		if err = replayThreadGroupPlans(root, plans); err != nil {
			t.Fatal(err)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runChild := func(t *testing.T, root, stage string, killed bool) {
		t.Helper()
		child := exec.Command(executable, "-test.run=^TestThreadGroupRecoveryProcessProgress$")
		child.Env = append(os.Environ(), "OIMO_REPLAY_CRASH_ROOT="+root, "OIMO_REPLAY_CRASH_STAGE="+stage)
		output, err := child.CombinedOutput()
		if !killed {
			if err != nil {
				t.Fatalf("recovery did not complete: %v %s", err, output)
			}
			return
		}
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			t.Fatalf("not SIGKILL: %v %s", err, output)
		}
		status, ok := exited.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("unexpected exit: %v %s", err, output)
		}
	}
	t.Run("six-interrupted-writes", func(t *testing.T) {
		f := newReplayFixture(t, []int{0, 0, 0})
		if err := closeThreadGroupReplays(f.plans); err != nil {
			t.Fatal(err)
		}
		var sizes []int64
		for _, p := range f.plans {
			for _, b := range p.blocks {
				sizes = append(sizes, int64(len(b)))
			}
		}
		var want int64
		for attempt, size := range sizes {
			runChild(t, f.parent, "write", true)
			want += size
			var got int64
			for _, p := range f.plans {
				info, err := os.Stat(filepath.Join(f.parent, fmt.Sprint(p.key), "delta-000001.wal"))
				if err != nil {
					t.Fatal(err)
				}
				got += info.Size() - p.start
			}
			if got != want {
				t.Fatal("recovery failed to advance", attempt+1, got, want)
			}
			if _, err := os.Stat(filepath.Join(f.parent, ThreadGroupFile)); err != nil {
				t.Fatal("redo lost during interrupted write", err)
			}
			t.Logf("SIGKILL %d: restored body bytes=%d", attempt+1, got)
		}
		// 全blockの一致後もSync/Closeを通し、7回目はWriteをせず完了する。
		runChild(t, f.parent, "write", false)
		if err := RecoverThreadCommitGroup(f.parent, f.owner, f.authorize); err != nil {
			t.Fatal(err)
		}
		verifyReplayThreads(t, f)
	})
	for _, stage := range []string{"sync", "close"} {
		t.Run(stage, func(t *testing.T) {
			f := newReplayFixture(t, []int{0, 0, 0})
			if err := closeThreadGroupReplays(f.plans); err != nil {
				t.Fatal(err)
			}
			runChild(t, f.parent, stage, true)
			if _, err := os.Stat(filepath.Join(f.parent, ThreadGroupFile)); err != nil {
				t.Fatal("redo lost during interrupted recovery", stage, err)
			}
			if err := RecoverThreadCommitGroup(f.parent, f.owner, f.authorize); err != nil {
				t.Fatal(err)
			}
			verifyReplayThreads(t, f)
		})
	}
}
