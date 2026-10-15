// 正本不要の期限切れ回収と、認証拒否・取消・payload削除途中からの再開を検証する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupReclaimWithKeysWithoutSource(t *testing.T) {
	cfg, backup := backupFixture(t)
	past := time.Now().Add(-25 * time.Hour)
	clock := func() time.Time { return past }
	if _, e := captureOfflineBackup(context.Background(), cfg, backup, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	keys := filepath.Join(filepath.Dir(backup), "separate-keys")
	if _, e := exportBackupKeys(context.Background(), cfg, backup, keys, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	before := func() time.Time { return past.Add(time.Minute) }
	unexpired, e := reclaimBackupWithKeys(context.Background(), backup, keys, true, before, func(string) error { return nil })
	if e != nil || unexpired.Expired || unexpired.Applied || unexpired.Verified || unexpired.RestoreReady {
		t.Fatal(unexpired, e)
	}
	regressed := func() time.Time { return past.Add(-time.Minute) }
	if _, e = reclaimBackupWithKeys(context.Background(), backup, keys, true, regressed, func(string) error { return nil }); e == nil {
		t.Fatal("clock regression accepted")
	}
	preview, e := ReclaimBackupWithKeys(context.Background(), backup, keys, false)
	if e != nil || !preview.Expired || preview.Applied {
		t.Fatal(preview, e)
	}
	manifest := filepath.Join(backup, "manifest.json")
	raw, e := os.ReadFile(manifest)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(manifest, append(append([]byte{}, raw...), '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupWithKeys(context.Background(), backup, keys, true); e == nil {
		t.Fatal("manifest binding not checked")
	}
	if e = os.WriteFile(manifest, raw, 0600); e != nil {
		t.Fatal(e)
	}
	unknown := filepath.Join(backup, "unlisted")
	if e = os.WriteFile(unknown, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupWithKeys(context.Background(), backup, keys, true); e == nil {
		t.Fatal("unknown payload accepted")
	}
	if e = os.Remove(unknown); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(keys, unknown); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupWithKeys(context.Background(), backup, keys, true); e == nil {
		t.Fatal("link accepted")
	}
	if e = os.Remove(unknown); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = ReclaimBackupWithKeys(ctx, backup, keys, true); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	stopped := errors.New("stop after first payload unlink")
	if _, e = reclaimBackupWithKeys(context.Background(), backup, keys, true, time.Now, func(string) error { return stopped }); !errors.Is(e, stopped) {
		t.Fatal(e)
	}
	if _, e = os.Stat(manifest); e != nil {
		t.Fatal("resume manifest missing", e)
	}
	if _, e = loadBackupKeys(context.Background(), keys); e != nil {
		t.Fatal("external keys changed", e)
	}
	report, e := ReclaimBackupWithKeys(context.Background(), backup, keys, true)
	if e != nil || !report.Expired || !report.Applied || report.Verified || report.RestoreReady {
		t.Fatal(report, e)
	}
	if _, e = os.Stat(backup); !os.IsNotExist(e) {
		t.Fatal("backup remains", e)
	}
	if _, e = loadBackupKeys(context.Background(), keys); e != nil {
		t.Fatal("external keys changed", e)
	}
}
