// 独立鍵による事前認証・鍵束喪失後の回収・中断再開と危険な対象の拒否を検査する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"oimobbs/internal/platform"
)

func independentReplayFixture(t *testing.T) (string, string, string) {
	t.Helper()
	backup, keys, root := staleReplayFixture(t)
	path := filepath.Join(filepath.Dir(backup), "cleanup.key")
	if e := InitializeReplayCleanupKey(path); e != nil {
		t.Fatal(e)
	}
	key, e := replayCleanupKey(keys)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key[:])
	raw, e := os.ReadFile(filepath.Join(root, backupReplayGate))
	if e != nil {
		t.Fatal(e)
	}
	plan, e := decodeReplayCleanupPlan(raw, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeIndependentReplayPlan(root, path, plan); e != nil {
		t.Fatal(e)
	}
	// 元バックアップ・鍵束・作業内masterを失っても独立回収が可能。
	for _, p := range []string{backup, keys} {
		if e = os.RemoveAll(p); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Remove(filepath.Join(root, "keys/master-000001.key")); e != nil {
		t.Fatal(e)
	}
	return root, path, keys
}

// SIGKILL後に正本・鍵束・本体を退避しても事前認証した領域だけを回収する。
func TestIndependentReplayCrash(t *testing.T) {
	if os.Getenv("OIMO_INDEPENDENT_REPLAY_CHILD") == "1" {
		_, e := verifyBackupReplayIndependent(context.Background(), os.Getenv("OIMO_REPLAY_BACKUP"), os.Getenv("OIMO_REPLAY_KEYS"), os.Getenv("OIMO_REPLAY_PARENT"), os.Getenv("OIMO_REPLAY_CLEANUP_KEY"), time.Now, func(root string) error {
			_, _ = os.Stdout.WriteString(root + "\n")
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		})
		t.Fatal("child did not stop", e)
	}
	cfg, backup, keys, parent := replayFixture(t)
	key := filepath.Join(filepath.Dir(parent), "cleanup.key")
	if e := InitializeReplayCleanupKey(key); e != nil {
		t.Fatal(e)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestIndependentReplayCrash$")
	command.Env = append(os.Environ(), "OIMO_INDEPENDENT_REPLAY_CHILD=1", "OIMO_REPLAY_BACKUP="+backup, "OIMO_REPLAY_KEYS="+keys, "OIMO_REPLAY_PARENT="+parent, "OIMO_REPLAY_CLEANUP_KEY="+key)
	output, e := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(e, &exit) {
		t.Fatal("child unexpectedly exited", e)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("wrong termination", e)
	}
	root := strings.TrimSpace(string(output))
	if filepath.Dir(root) != parent {
		t.Fatal("missing owned root")
	}
	for _, path := range []string{cfg.DataDir, backup, keys} {
		if e = os.Rename(path, path+"-unavailable"); e != nil {
			t.Fatal(e)
		}
	}
	report, e := ReclaimBackupReplayWithCleanupKey(context.Background(), root, key, true)
	if e != nil || !report.Applied || report.RestoreReady {
		t.Fatal(report, e)
	}
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("crashed copy retained", e)
	}
}

func TestIndependentReplayMaintenanceAndKeyChange(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(map[bool]string{false: "cycle", true: "key-change"}[change], func(t *testing.T) {
			root, key, _ := independentReplayFixture(t)
			o := ReplayMaintenanceOptions{filepath.Dir(root), key, 1, time.Minute, 30 * time.Second, true}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			count := 0
			emit := func(report ReplayMaintenanceReport) error {
				count++
				if report.Status != "completed" {
					t.Fatal(report)
				}
				if count == 1 && (len(report.Sweep.Items) != 1 || report.Sweep.Items[0].Status != "reclaimed") {
					t.Fatal(report)
				}
				if count == 2 {
					cancel()
				}
				return nil
			}
			wait := func(context.Context, time.Duration) error {
				if change {
					if e := os.Remove(key); e != nil {
						t.Fatal(e)
					}
					if e := InitializeReplayCleanupKey(key); e != nil {
						t.Fatal(e)
					}
				}
				return nil
			}
			e := runReplayMaintenanceMode(ctx, o, emit, wait, SweepBackupReplayWithCleanupKey, true)
			if change {
				if e == nil || count != 1 {
					t.Fatal("changed key accepted", count, e)
				}
			} else if !errors.Is(e, context.Canceled) || count != 2 {
				t.Fatal(count, e)
			}
		})
	}
}

func TestOnlineReplayIndependentLostBundles(t *testing.T) {
	r, o, roots := onlineReplayFixture(t)
	o.CleanupKey = onlineOutput(t, "independent-cleanup.key")
	if e := InitializeReplayCleanupKey(o.CleanupKey); e != nil {
		t.Fatal(e)
	}
	prepared, e := r.PrepareNextOnlineBackup(context.Background(), o, OnlineBackupSiteOptions{})
	if e != nil || prepared.Preparation == nil || !prepared.Preparation.Complete {
		t.Fatal(prepared, e)
	}
	names, e := boundedBackupNames(context.Background(), o.KeysParent, "", validBackupSweepName)
	if e != nil {
		t.Fatal(e)
	}
	for _, root := range roots {
		raw, e := readPrivate(filepath.Join(root, backupReplayGate), replayCleanupLimit)
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, name := range names {
			key, e := replayCleanupKey(filepath.Join(o.KeysParent, name))
			if e != nil {
				t.Fatal(e)
			}
			plan, e := decodeReplayCleanupPlan(raw, key)
			clear(key[:])
			if e != nil {
				continue
			}
			if e = writeIndependentReplayPlan(root, o.CleanupKey, plan); e != nil {
				t.Fatal(e)
			}
			found = true
			break
		}
		if !found {
			t.Fatal("fixture plan not authenticated")
		}
	}
	for _, name := range names {
		if e = os.RemoveAll(filepath.Join(o.KeysParent, name)); e != nil {
			t.Fatal(e)
		}
	}
	report, e := sweepOnlineReplay(context.Background(), o, "", 128, false)
	if e != nil || len(report.Items) != 2 {
		t.Fatal(report, e)
	}
	for _, item := range report.Items {
		if item.Status != "verified" {
			t.Fatal(item)
		}
	}
	report, e = sweepOnlineReplay(context.Background(), o, "", 128, true)
	if e != nil || len(report.Items) != 2 {
		t.Fatal(report, e)
	}
	for _, item := range report.Items {
		if item.Status != "reclaimed" {
			t.Fatal(item)
		}
	}
	// 周期の固定identityにも独立鍵変更を含める。
	before, e := preparationIdentity(r.cfg, o)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(o.CleanupKey); e != nil {
		t.Fatal(e)
	}
	if e = InitializeReplayCleanupKey(o.CleanupKey); e != nil {
		t.Fatal(e)
	}
	after, e := preparationIdentity(r.cfg, o)
	if e != nil || before == after {
		t.Fatal("maintenance ignored independent key change", e)
	}
}

func TestIndependentReplayLossAndResume(t *testing.T) {
	root, key, keys := independentReplayFixture(t)
	if _, e := ReclaimBackupReplay(context.Background(), root, keys, true); e == nil {
		t.Fatal("lost bundle accepted")
	}
	preview, e := ReclaimBackupReplayWithCleanupKey(context.Background(), root, key, false)
	if e != nil || preview.Applied || preview.RestoreReady || preview.PlannedFiles < 10 {
		t.Fatal(preview, e)
	}
	stop := errors.New("injected interruption")
	if _, e = reclaimIndependentReplay(context.Background(), root, key, true, func(string) error { return stop }); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, independentReplayGate)); e != nil {
		t.Fatal(e)
	}
	// 元の印が既に除去済みでも、独立印を最後まで残して再開できる。
	if e = os.Remove(filepath.Join(root, backupReplayGate)); e != nil {
		t.Fatal(e)
	}
	result, e := ReclaimBackupReplayWithCleanupKey(context.Background(), root, key, true)
	if e != nil || !result.Applied || result.RestoreReady {
		t.Fatal(result, e)
	}
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	if _, e = os.Stat(key); e != nil {
		t.Fatal("cleanup key removed", e)
	}
}

func TestIndependentReplayRejectsBeforeMutation(t *testing.T) {
	for _, kind := range []string{"wrong-key", "tampered", "extra", "hardlink", "symlink", "relocated", "busy", "missing-lock", "missing-plan"} {
		t.Run(kind, func(t *testing.T) {
			root, key, _ := independentReplayFixture(t)
			var unlock func()
			switch kind {
			case "wrong-key":
				key += ".wrong"
				if e := InitializeReplayCleanupKey(key); e != nil {
					t.Fatal(e)
				}
			case "tampered":
				path := filepath.Join(root, independentReplayGate)
				raw, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				var env backupEnvelope
				if e = json.Unmarshal(raw, &env); e != nil {
					t.Fatal(e)
				}
				var plan replayCleanupPlan
				if e = json.Unmarshal(env.Manifest, &plan); e != nil {
					t.Fatal(e)
				}
				plan.Root += "-other"
				env.Manifest, _ = json.Marshal(plan)
				env.SHA = sha256.Sum256(env.Manifest)
				raw, _ = json.Marshal(env)
				if e = os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
			case "extra":
				if e := os.WriteFile(filepath.Join(root, "unlisted"), []byte("keep"), 0600); e != nil {
					t.Fatal(e)
				}
			case "hardlink", "symlink":
				path := filepath.Join(root, "keys/evidence-000010.seed")
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
				var e error
				if kind == "hardlink" {
					e = os.Link(key, path)
				} else {
					e = os.Symlink(key, path)
				}
				if e != nil {
					t.Fatal(e)
				}
			case "relocated":
				next := root + "-moved"
				if e := os.Rename(root, next); e != nil {
					t.Fatal(e)
				}
				root = next
			case "busy":
				lock, e := platform.Lock(root)
				if e != nil {
					t.Fatal(e)
				}
				unlock = func() { _ = platform.Unlock(lock) }
			case "missing-lock":
				if e := os.Remove(filepath.Join(root, ".lock")); e != nil {
					t.Fatal(e)
				}
			case "missing-plan":
				if e := os.Remove(filepath.Join(root, independentReplayGate)); e != nil {
					t.Fatal(e)
				}
			}
			if unlock != nil {
				defer unlock()
			}
			for _, apply := range []bool{false, true} {
				report, e := ReclaimBackupReplayWithCleanupKey(context.Background(), root, key, apply)
				if e == nil || report.Applied {
					t.Fatal("unsafe root accepted", report, e)
				}
			}
			if _, e := os.Stat(filepath.Join(root, "instance.json")); e != nil {
				t.Fatal("payload mutated before validation", e)
			}
		})
	}
}

func TestIndependentReplayPreparationAndSweep(t *testing.T) {
	_, backup, keys, parent := replayFixture(t)
	key := filepath.Join(filepath.Dir(parent), "cleanup.key")
	if e := InitializeReplayCleanupKey(key); e != nil {
		t.Fatal(e)
	}
	initial, _ := os.ReadFile(key)
	if e := InitializeReplayCleanupKey(key); e == nil {
		t.Fatal("existing key overwritten")
	}
	after, _ := os.ReadFile(key)
	if string(initial) != string(after) {
		t.Fatal("key changed")
	}
	checked := false
	report, e := verifyBackupReplayIndependent(context.Background(), backup, keys, parent, key, time.Now, func(root string) error {
		checked = true
		if _, e := os.Stat(filepath.Join(root, independentReplayGate)); e != nil {
			return e
		}
		// writer排他が独立回収にも効く。
		if _, e := ReclaimBackupReplayWithCleanupKey(context.Background(), root, key, true); !errors.Is(e, errReplayRootBusy) {
			return errors.New("active root accepted")
		}
		return nil
	})
	if e != nil || !checked || !report.Replayed || report.RestoreReady {
		t.Fatal(report, e)
	}
	root, cleanup, _ := independentReplayFixture(t)
	sweep, e := SweepBackupReplayWithCleanupKey(context.Background(), filepath.Dir(root), cleanup, "", 1, true)
	if e != nil || len(sweep.Items) != 1 || sweep.Items[0].Status != "reclaimed" || sweep.RestoreReady {
		t.Fatal(sweep, e)
	}
}
