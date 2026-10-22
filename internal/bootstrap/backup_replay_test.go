// 正本なしの全再生、公開起動の遮断、コピーの不変性と作業領域の除去を検証する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func replayFixture(t *testing.T) (Config, string, string, string) {
	t.Helper()
	cfg, backup := backupFixture(t)
	if _, e := CaptureOfflineBackup(context.Background(), cfg, backup); e != nil {
		t.Fatal(e)
	}
	keys := filepath.Join(filepath.Dir(backup), "separate-keys")
	if _, e := ExportBackupKeys(context.Background(), cfg, backup, keys); e != nil {
		t.Fatal(e)
	}
	parent := filepath.Join(filepath.Dir(backup), "work")
	if e := os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	return cfg, backup, keys, parent
}
func TestBackupReplaySourceUnavailable(t *testing.T) {
	cfg, backup, keys, parent := replayFixture(t)
	if e := os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	checked := false
	report, e := verifyBackupReplay(context.Background(), backup, keys, parent, time.Now, func(root string) error {
		checked = true
		probe := cfg
		probe.DataDir = root
		if _, e := checkLockedPosting(probe, false, true); e == nil {
			return errors.New("replay startup gate missing")
		}
		if r, e := OpenPostingRepository(probe, postcapture.Validate); e == nil {
			r.Close()
			return errors.New("replay directory publicly startable")
		}
		return nil
	})
	if e != nil || !report.Verified || !report.Replayed || report.RestoreReady || !checked {
		t.Fatal(report, e)
	}
	entries, e := os.ReadDir(parent)
	if e != nil || len(entries) != 0 {
		t.Fatal("work retained", entries, e)
	}
	if _, e = VerifyBackupWithKeys(context.Background(), backup, keys); e != nil {
		t.Fatal("input changed", e)
	}
}
func TestBackupReplayFailureCleanup(t *testing.T) {
	for _, kind := range []string{"cancel", "checkpoint", "expired", "nested", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			_, backup, keys, parent := replayFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clock := time.Now
			checkpoint := func(string) error { return nil }
			switch kind {
			case "cancel":
				checkpoint = func(string) error { cancel(); return nil }
			case "checkpoint":
				checkpoint = func(string) error { return errors.New("interrupted") }
			case "expired":
				checkpoint = func(string) error {
					bundle, e := loadBackupKeys(ctx, keys)
					if e != nil {
						return e
					}
					clock = func() time.Time { return time.Unix(0, int64(bundle.Expires)) }
					return nil
				}
			case "nested":
				parent = backup
			case "permissions":
				if e := os.Chmod(parent, 0755); e != nil {
					t.Fatal(e)
				}
			}
			report, e := verifyBackupReplay(ctx, backup, keys, parent, func() time.Time { return clock() }, checkpoint)
			if e == nil || report.Replayed || report.Verified || report.RestoreReady {
				t.Fatal(report, e)
			}
			if kind != "nested" {
				entries, e := os.ReadDir(parent)
				if e != nil || len(entries) != 0 {
					t.Fatal("failed work retained", entries, e)
				}
			}
		})
	}
}

// 認証鍵を持つfixture側でCRC不正WALとそのSHA/MACを揃え、再生で初めて拒否する。
func TestBackupReplayRejectsAuthenticatedBadWAL(t *testing.T) {
	_, backup, keys, parent := replayFixture(t)
	raw, e := readPrivate(filepath.Join(backup, "manifest.json"), backupManifestLimit)
	if e != nil {
		t.Fatal(e)
	}
	bundle, e := loadBackupKeys(context.Background(), keys)
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
	changed := false
	for i, entry := range m.Entries {
		if entry.Kind != "thread" {
			continue
		}
		dir := filepath.Join(backup, backupEntryPath(entry))
		current, _, e := store.InspectThreadFiles(dir)
		if e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(dir, current.Delta.File)
		contents, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		contents[len(contents)-1] ^= 1
		if e = os.WriteFile(p, contents, 0600); e != nil {
			t.Fatal(e)
		}
		current.Delta.RequiredSHA = sha256.Sum256(contents)
		encoded, e := store.EncodeCurrent(current)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, "current.json"), encoded, 0600); e != nil {
			t.Fatal(e)
		}
		for j, f := range entry.Files {
			switch f.Name {
			case current.Delta.File:
				m.Entries[i].Files[j].SHA = current.Delta.RequiredSHA
			case "current.json":
				m.Entries[i].Files[j].SHA = sha256.Sum256(encoded)
				m.Entries[i].Files[j].Length = domain.U64(len(encoded))
			}
		}
		changed = true
		break
	}
	if !changed {
		t.Fatal("no thread")
	}
	raw, e = encodeBackupManifest(m, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(backup, "manifest.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	bundle.BackupSHA = sha256.Sum256(raw)
	bundleKey, e := backupKeysKey(keys)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(bundleKey[:])
	raw, e = encodeBackupKeys(bundle, bundleKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(keys, "bundle.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyBackupWithKeys(context.Background(), backup, keys); e != nil {
		t.Fatal("hash-only fixture rejected before replay", e)
	}
	report, e := VerifyBackupReplay(context.Background(), backup, keys, parent)
	if e == nil || report.Replayed || report.Verified {
		t.Fatal("bad WAL replay accepted", report, e)
	}
	entries, e := os.ReadDir(parent)
	if e != nil || len(entries) != 1 || len(entries) == 1 && entries[0].Name() != ".lock" {
		t.Fatal(entries, e)
	}
}

func TestBackupReplayExpiredProvisioningJob(t *testing.T) {
	cfg, base := backupFixture(t)
	backup := base + "-expired-job"
	now := time.Now().Add(31 * 24 * time.Hour)
	clock := func() time.Time { return now }
	if _, e := captureOfflineBackup(context.Background(), cfg, backup, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	keys := filepath.Join(filepath.Dir(base), "expired-job-keys")
	if _, e := exportBackupKeys(context.Background(), cfg, backup, keys, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	parent := filepath.Join(filepath.Dir(base), "work")
	if e := os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	report, e := verifyBackupReplay(context.Background(), backup, keys, parent, clock, func(root string) error {
		entries, e := os.ReadDir(filepath.Join(root, "jobs"))
		if e != nil {
			return e
		}
		if len(entries) != 0 {
			return errors.New("expired job regenerated")
		}
		return nil
	})
	if e != nil || !report.Replayed || report.RestoreReady {
		t.Fatal(report, e)
	}
}

func TestBackupReplayControlSnapshot(t *testing.T) {
	cfg, backup := backupFixture(t)
	r, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	installRuntimeFixture(t, cfg, r, 13)
	if _, e = CaptureOfflineBackup(context.Background(), cfg, backup); e != nil {
		t.Fatal(e)
	}
	keys := filepath.Join(filepath.Dir(backup), "keys-copy")
	if _, e = ExportBackupKeys(context.Background(), cfg, backup, keys); e != nil {
		t.Fatal(e)
	}
	parent := filepath.Join(filepath.Dir(backup), "work")
	if e = os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	report, e := VerifyBackupReplay(context.Background(), backup, keys, parent)
	if e != nil || !report.Replayed || report.RestoreReady {
		t.Fatal(report, e)
	}
}
