// 鍵の別保管と正本なしの照合、取り違え・改変・期限・不完全出力を検証する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupKeysSourceUnavailable(t *testing.T) {
	cfg, backup := backupFixture(t)
	captured, err := CaptureOfflineBackup(context.Background(), cfg, backup)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(filepath.Dir(backup), "separate-keys")
	exported, err := ExportBackupKeys(context.Background(), cfg, backup, bundle)
	if err != nil || !exported.Verified || exported.RestoreReady || exported.ID != captured.ID || exported.Expires != captured.Expires {
		t.Fatal(exported, err)
	}
	if _, err = ExportBackupKeys(context.Background(), cfg, backup, bundle); err == nil {
		t.Fatal("existing key bundle reused")
	}
	if err = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyBackupWithKeys(context.Background(), backup, bundle)
	if err != nil || !verified.Verified || verified.RestoreReady || verified.Bytes != captured.Bytes {
		t.Fatal(verified, err)
	}
	if _, err = verifyBackupWithKeys(context.Background(), backup, bundle, func() time.Time { return time.Unix(0, int64(captured.Expires)) }); err == nil {
		t.Fatal("expired keys verified")
	}
	if _, err = verifyBackupWithKeys(context.Background(), backup, bundle, func() time.Time { return time.Unix(0, 1) }); err == nil {
		t.Fatal("clock regression accepted")
	}
}

func TestBackupKeysRejectTamper(t *testing.T) {
	for _, kind := range []string{"master", "seed", "instance", "manifest", "rehash", "missing", "extra", "symlink", "hardlink", "backup-payload", "backup-manifest", "other-backup"} {
		t.Run(kind, func(t *testing.T) {
			cfg, backup := backupFixture(t)
			if _, err := CaptureOfflineBackup(context.Background(), cfg, backup); err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(filepath.Dir(backup), "keys-copy")
			if _, err := ExportBackupKeys(context.Background(), cfg, backup, bundle); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "master", "seed", "instance":
				name := map[string]string{"master": "keys/master-000001.key", "seed": "keys/evidence-000010.seed", "instance": "instance.json"}[kind]
				p := filepath.Join(bundle, name)
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				raw[0] ^= 1
				if err = os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest", "rehash":
				p := filepath.Join(bundle, "bundle.json")
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				var env backupEnvelope
				if err = json.Unmarshal(raw, &env); err != nil {
					t.Fatal(err)
				}
				var m map[string]any
				if err = json.Unmarshal(env.Manifest, &m); err != nil {
					t.Fatal(err)
				}
				m["expires_at_ns"] = "9223372036854775807"
				env.Manifest, _ = json.Marshal(m)
				if kind == "rehash" {
					env.SHA = sha256.Sum256(env.Manifest)
				}
				raw, _ = json.Marshal(env)
				if err = os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(filepath.Join(bundle, "keys/evidence-000010.seed")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(bundle, "unlisted"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				p := filepath.Join(bundle, "keys/evidence-000010.seed")
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(filepath.Dir(backup), "external-seed")
				if err = os.WriteFile(target, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(target, p)
				} else {
					err = os.Link(target, p)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "backup-payload":
				key, err := backupKey(cfg.DataDir)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(key[:])
				raw, err := os.ReadFile(filepath.Join(backup, "manifest.json"))
				if err != nil {
					t.Fatal(err)
				}
				var marker instance
				b, _ := os.ReadFile(filepath.Join(cfg.DataDir, "instance.json"))
				json.Unmarshal(b, &marker)
				m, _, err := decodeBackupManifest(raw, key, marker.SiteID)
				if err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(backup, backupEntryPath(m.Entries[0]), m.Entries[0].Files[0].Name)
				b, err = os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				b[0] ^= 1
				if err = os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "backup-manifest":
				p := filepath.Join(backup, "manifest.json")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(p, append(b, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "other-backup":
				other := filepath.Join(filepath.Dir(backup), "other-copy")
				if _, err := CaptureOfflineBackup(context.Background(), cfg, other); err != nil {
					t.Fatal(err)
				}
				backup = other
			}
			if _, err := VerifyBackupWithKeys(context.Background(), backup, bundle); err == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
}

func TestBackupKeysOutputBoundaries(t *testing.T) {
	cfg, backup := backupFixture(t)
	captured, err := CaptureOfflineBackup(context.Background(), cfg, backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{backup, filepath.Join(backup, "keys-copy"), filepath.Dir(backup), filepath.Join(cfg.DataDir, "keys-copy"), "relative"} {
		if _, err = ExportBackupKeys(context.Background(), cfg, backup, output); err == nil {
			t.Fatal("unsafe output accepted", output)
		}
	}
	out := filepath.Join(filepath.Dir(backup), "cancelled")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = ExportBackupKeys(ctx, cfg, backup, out); err == nil {
		t.Fatal("cancel ignored")
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("cancelled export created output", err)
	}
	if _, err = exportBackupKeys(context.Background(), cfg, backup, out, func() time.Time { return time.Unix(0, int64(captured.Expires)) }, func(string) {}); err == nil {
		t.Fatal("expired copy exported")
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("expired export created output", err)
	}
	clock := time.Now
	if _, err = exportBackupKeys(context.Background(), cfg, backup, out, func() time.Time { return clock() }, func(point string) {
		if point == "backup-keys:manifest_synced" {
			clock = func() time.Time { return time.Unix(0, int64(captured.Expires)) }
		}
	}); err == nil {
		t.Fatal("export completed after deadline")
	}
	if _, err = VerifyBackupWithKeys(context.Background(), backup, out); err == nil {
		t.Fatal("partial bundle accepted")
	}
	if _, err = ExportBackupKeys(context.Background(), cfg, backup, out); err == nil {
		t.Fatal("partial output reused")
	}
}

func TestBackupKeysDeadlineDuringVerification(t *testing.T) {
	cfg, backup := backupFixture(t)
	captured, err := CaptureOfflineBackup(context.Background(), cfg, backup)
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(filepath.Dir(backup), "separate-keys")
	if _, err = ExportBackupKeys(context.Background(), cfg, backup, keys); err != nil {
		t.Fatal(err)
	}
	calls := 0
	clock := func() time.Time {
		calls++
		if calls > 1 {
			return time.Unix(0, int64(captured.Expires))
		}
		return time.Now()
	}
	if _, err = verifyBackupWithKeys(context.Background(), backup, keys, clock); err == nil {
		t.Fatal("deadline reached during verification accepted")
	}
	calls = 0
	if _, err = verifyOfflineBackup(context.Background(), cfg, backup, clock); err == nil {
		t.Fatal("source-key verification deadline ignored")
	}
}

func TestBackupKeysReclaimResume(t *testing.T) {
	cfg, backup := backupFixture(t)
	captured, err := CaptureOfflineBackup(context.Background(), cfg, backup)
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(filepath.Dir(backup), "separate-keys")
	if _, err = ExportBackupKeys(context.Background(), cfg, backup, keys); err != nil {
		t.Fatal(err)
	}
	before, err := ReclaimBackupKeys(context.Background(), cfg, keys, true)
	if err != nil || before.Applied || before.Expired {
		t.Fatal(before, err)
	}
	clock := func() time.Time { return time.Unix(0, int64(captured.Expires)) }
	preview, err := reclaimBackupKeys(context.Background(), cfg, keys, false, clock, func(string) error { return nil })
	if err != nil || preview.Applied || !preview.Expired || preview.Verified || preview.Files != 3 {
		t.Fatal(preview, err)
	}
	stop := errors.New("interrupted after master removal")
	if _, err = reclaimBackupKeys(context.Background(), cfg, keys, true, clock, func(string) error {
		if _, e := os.Stat(filepath.Join(keys, "keys/master-000001.key")); os.IsNotExist(e) {
			return stop
		}
		return nil
	}); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(keys, "bundle.json")); err != nil {
		t.Fatal("recovery manifest removed", err)
	}
	if _, err = VerifyBackupWithKeys(context.Background(), backup, keys); err == nil {
		t.Fatal("partial reclamation verified")
	}
	resumed, err := reclaimBackupKeys(context.Background(), cfg, keys, true, clock, func(string) error { return nil })
	if err != nil || !resumed.Applied || !resumed.Expired {
		t.Fatal(resumed, err)
	}
	if _, err = os.Stat(keys); !os.IsNotExist(err) {
		t.Fatal("key bundle remains", err)
	}
	if _, err = VerifyOfflineBackup(context.Background(), cfg, backup); err != nil {
		t.Fatal("backup altered by key reclamation", err)
	}
}

func TestBackupKeysReclaimRefusesUntrustedInventory(t *testing.T) {
	for _, kind := range []string{"manifest", "extra", "symlink", "hardlink", "partial", "clock"} {
		t.Run(kind, func(t *testing.T) {
			cfg, backup := backupFixture(t)
			captured, err := CaptureOfflineBackup(context.Background(), cfg, backup)
			if err != nil {
				t.Fatal(err)
			}
			keys := filepath.Join(filepath.Dir(backup), "separate-keys")
			if _, err = ExportBackupKeys(context.Background(), cfg, backup, keys); err != nil {
				t.Fatal(err)
			}
			clock := func() time.Time { return time.Unix(0, int64(captured.Expires)) }
			switch kind {
			case "manifest":
				if err = os.WriteFile(filepath.Join(keys, "bundle.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err = os.WriteFile(filepath.Join(keys, "extra"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "partial":
				if err = os.Rename(filepath.Join(keys, "bundle.json"), filepath.Join(keys, "bundle.pending")); err != nil {
					t.Fatal(err)
				}
			case "clock":
				clock = func() time.Time { return time.Unix(0, 1) }
			case "symlink", "hardlink":
				original := filepath.Join(cfg.DataDir, "keys/master-000001.key")
				target := filepath.Join(keys, "keys/master-000001.key")
				if err = os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(original, target)
				} else {
					err = os.Link(original, target)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = reclaimBackupKeys(context.Background(), cfg, keys, true, clock, func(string) error { return nil }); err == nil {
				t.Fatal("untrusted reclamation accepted")
			}
			if _, err = os.Stat(filepath.Join(keys, "keys/evidence-000010.seed")); err != nil {
				t.Fatal("reclamation mutated payload", err)
			}
		})
	}
}
