// 強制終了した再生領域の認証付き回収・排他・中断再開と、危険な対象の拒否を検証する。
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

func staleReplayFixture(t *testing.T) (string, string, string) {
	return staleReplayFixtureAt(t, time.Now)
}
func staleReplayFixtureAt(t *testing.T, clock func() time.Time) (string, string, string) {
	t.Helper()
	cfg, backup := backupFixture(t)
	if _, e := captureOfflineBackup(context.Background(), cfg, backup, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	keys := filepath.Join(filepath.Dir(backup), "separate-keys")
	if _, e := exportBackupKeys(context.Background(), cfg, backup, keys, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	parent := filepath.Join(filepath.Dir(backup), "work")
	if e := os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	bundle, e := loadBackupKeys(context.Background(), keys)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := readPrivate(filepath.Join(backup, "manifest.json"), backupManifestLimit)
	if e != nil {
		t.Fatal(e)
	}
	key, e := backupKey(keys)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key[:])
	m, _, e := decodeBackupManifest(raw, key, bundle.Site)
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.MkdirTemp(parent, ".backup-replay-")
	if e != nil {
		t.Fatal(e)
	}
	lock, e := platform.Lock(root)
	if e != nil {
		t.Fatal(e)
	}
	defer platform.Unlock(lock)
	if _, e = writeReplayCleanupPlan(root, keys, m, bundle.BackupSHA, clock()); e != nil {
		t.Fatal(e)
	}
	if e = materializeBackupReplay(context.Background(), backup, keys, root, m, clock); e != nil {
		t.Fatal(e)
	}
	return backup, keys, root
}
func TestReplayCleanupPreviewResume(t *testing.T) {
	backup, keys, root := staleReplayFixture(t)
	preview, e := ReclaimBackupReplay(context.Background(), root, keys, false)
	if e != nil || preview.Applied || preview.PlannedFiles < 10 || preview.RestoreReady {
		t.Fatal(preview, e)
	}
	stop := errors.New("stopped after copied master removal")
	if _, e = reclaimBackupReplay(context.Background(), root, keys, true, func(string) error {
		if _, e := os.Stat(filepath.Join(root, "keys/master-000001.key")); os.IsNotExist(e) {
			return stop
		}
		return nil
	}); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	for _, name := range []string{backupReplayGate, ".lock"} {
		if _, e = os.Stat(filepath.Join(root, name)); e != nil {
			t.Fatal("resume boundary missing", name, e)
		}
	}
	resumed, e := ReclaimBackupReplay(context.Background(), root, keys, true)
	if e != nil || !resumed.Applied || resumed.RestoreReady {
		t.Fatal(resumed, e)
	}
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("work remains", e)
	}
	if _, e = VerifyBackupWithKeys(context.Background(), backup, keys); e != nil {
		t.Fatal("original copy changed", e)
	}
}
func TestReplayCleanupRefusesActiveWorker(t *testing.T) {
	_, keys, root := staleReplayFixture(t)
	lock, e := platform.Lock(root)
	if e != nil {
		t.Fatal(e)
	}
	defer platform.Unlock(lock)
	for _, apply := range []bool{false, true} {
		if _, e = ReclaimBackupReplay(context.Background(), root, keys, apply); e == nil {
			t.Fatal("active work reclaimed")
		}
	}
	if _, e = os.Stat(filepath.Join(root, "keys/master-000001.key")); e != nil {
		t.Fatal(e)
	}
}
func TestReplayCleanupRejectsUnsafeTargets(t *testing.T) {
	for _, kind := range []string{"manifest", "rehash", "extra", "symlink", "hardlink", "relocated", "wrong-keys", "legacy", "missing-lock"} {
		t.Run(kind, func(t *testing.T) {
			backup, keys, root := staleReplayFixture(t)
			originalKeys := keys
			gate := filepath.Join(root, backupReplayGate)
			switch kind {
			case "manifest", "rehash":
				raw, e := os.ReadFile(gate)
				if e != nil {
					t.Fatal(e)
				}
				var env backupEnvelope
				if e = json.Unmarshal(raw, &env); e != nil {
					t.Fatal(e)
				}
				var m map[string]any
				if e = json.Unmarshal(env.Manifest, &m); e != nil {
					t.Fatal(e)
				}
				m["root"] = filepath.Dir(root)
				env.Manifest, _ = json.Marshal(m)
				if kind == "rehash" {
					env.SHA = sha256.Sum256(env.Manifest)
				}
				raw, _ = json.Marshal(env)
				if e = os.WriteFile(gate, raw, 0600); e != nil {
					t.Fatal(e)
				}
			case "legacy":
				if e := os.WriteFile(gate, []byte("{\"mode\":\"verification_only\"}"), 0600); e != nil {
					t.Fatal(e)
				}
			case "extra":
				if e := os.WriteFile(filepath.Join(root, "unlisted"), []byte("x"), 0600); e != nil {
					t.Fatal(e)
				}
			case "symlink", "hardlink":
				target := filepath.Join(root, "keys/master-000001.key")
				source := filepath.Join(keys, "keys/master-000001.key")
				if e := os.Remove(target); e != nil {
					t.Fatal(e)
				}
				var e error
				if kind == "symlink" {
					e = os.Symlink(source, target)
				} else {
					e = os.Link(source, target)
				}
				if e != nil {
					t.Fatal(e)
				}
			case "relocated":
				newRoot := root + "-moved"
				if e := os.Rename(root, newRoot); e != nil {
					t.Fatal(e)
				}
				root = newRoot
			case "wrong-keys":
				cfg, other := backupFixture(t)
				if _, e := CaptureOfflineBackup(context.Background(), cfg, other); e != nil {
					t.Fatal(e)
				}
				otherKeys := filepath.Join(filepath.Dir(other), "keys-copy")
				if _, e := ExportBackupKeys(context.Background(), cfg, other, otherKeys); e != nil {
					t.Fatal(e)
				}
				keys = otherKeys
			case "missing-lock":
				if e := os.Remove(filepath.Join(root, ".lock")); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := ReclaimBackupReplay(context.Background(), root, keys, true); e == nil {
				t.Fatal("unsafe cleanup accepted")
			}
			if _, e := os.Stat(filepath.Join(root, "keys/evidence-000010.seed")); e != nil {
				t.Fatal("payload changed before rejection", e)
			}
			if kind != "hardlink" {
				if _, e := VerifyBackupWithKeys(context.Background(), backup, originalKeys); e != nil {
					t.Fatal("input changed", e)
				}
			}
		})
	}
}
func TestReplayCleanupCrash(t *testing.T) {
	if os.Getenv("OIMO_REPLAY_CRASH_CHILD") == "1" {
		_, e := verifyBackupReplay(context.Background(), os.Getenv("OIMO_REPLAY_BACKUP"), os.Getenv("OIMO_REPLAY_KEYS"), os.Getenv("OIMO_REPLAY_PARENT"), time.Now, func(root string) error {
			os.Stdout.WriteString(root + "\n")
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		})
		t.Fatal("child did not stop", e)
	}
	cfg, backup, keys, parent := replayFixture(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestReplayCleanupCrash$")
	cmd.Env = append(os.Environ(), "OIMO_REPLAY_CRASH_CHILD=1", "OIMO_REPLAY_BACKUP="+backup, "OIMO_REPLAY_KEYS="+keys, "OIMO_REPLAY_PARENT="+parent)
	output, e := cmd.CombinedOutput()
	var failure *exec.ExitError
	if !errors.As(e, &failure) {
		t.Fatal("child unexpectedly exited", e)
	}
	status, ok := failure.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("unexpected termination", e)
	}
	root := strings.TrimSpace(string(output))
	if filepath.Dir(root) != parent {
		t.Fatal("child did not report owned work root")
	}
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupReplay(context.Background(), root, keys, false); e != nil {
		t.Fatal(e)
	}
	report, e := ReclaimBackupReplay(context.Background(), root, keys, true)
	if e != nil || !report.Applied {
		t.Fatal(report, e)
	}
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("crashed work remains", e)
	}
}

func TestReplayCleanupExpiredBundle(t *testing.T) {
	old := time.Now().Add(-25 * time.Hour)
	backup, keys, root := staleReplayFixtureAt(t, func() time.Time { return old })
	if _, e := VerifyBackupWithKeys(context.Background(), backup, keys); e == nil {
		t.Fatal("expired copy verified")
	}
	report, e := ReclaimBackupReplay(context.Background(), root, keys, true)
	if e != nil || !report.Applied {
		t.Fatal("expired work retained", report, e)
	}
	if _, e = os.Stat(keys); e != nil {
		t.Fatal("external keys removed", e)
	}
}
func TestReplayCleanupCancellationResume(t *testing.T) {
	_, keys, root := staleReplayFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, e := reclaimBackupReplay(ctx, root, keys, true, func(string) error { cancel(); return nil }); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := ReclaimBackupReplay(context.Background(), root, keys, true); e != nil {
		t.Fatal(e)
	}
}

func TestReplayCleanupDuringNormalCompletion(t *testing.T) {
	_, keys, root := staleReplayFixture(t)
	key, e := replayCleanupKey(keys)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key[:])
	raw, e := readPrivate(filepath.Join(root, backupReplayGate), replayCleanupLimit)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := decodeReplayCleanupPlan(raw, key)
	if e != nil {
		t.Fatal(e)
	}
	stop := errors.New("completion cleanup interrupted")
	if e = cleanupOwnedReplayRoot(root, plan, func(string) error { return stop }); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, backupReplayGate)); e != nil {
		t.Fatal("completion lost recovery plan", e)
	}
	report, e := ReclaimBackupReplay(context.Background(), root, keys, true)
	if e != nil || !report.Applied {
		t.Fatal(report, e)
	}
}
