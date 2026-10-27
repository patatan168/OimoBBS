// 複数のオンライン鍵束に対応する作業回収と、鍵を消す前の全page確認を検査する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/platform"
)

// onlineReplayFixture は同じsiteの別々の捕捉に束縛した2つの再生停止領域を作る。
func onlineReplayFixture(t *testing.T) (*Repository, BackupPreparationMaintenanceOptions, []string) {
	t.Helper()
	cfg, r := adminFixture(t)
	t.Cleanup(func() { r.Close() })
	if _, e := r.CreateBoard(context.Background(), "replays", "再生回収"); e != nil {
		t.Fatal(e)
	}
	o := BackupPreparationMaintenanceOptions{CopyParent: expiredSweepParent(t), KeysParent: expiredSweepParent(t), PartialPlanParent: expiredSweepParent(t), PartialKeysPlanParent: expiredSweepParent(t), KeysPlanParent: expiredSweepParent(t), PairPlanParent: expiredSweepParent(t), WorkParent: expiredSweepParent(t), ControlParent: expiredSweepParent(t), TrustInstance: onlineOutput(t, "trust.json"), Budget: time.Minute, Interval: time.Hour, Apply: true, Reclaim: true}
	raw, e := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeNew(o.TrustInstance, raw); e != nil {
		t.Fatal(e)
	}
	roots := []string{}
	for _, name := range []string{".backup-replay-a", ".backup-replay-b"} {
		prepared, e := r.PrepareNextOnlineBackup(context.Background(), o, OnlineBackupSiteOptions{})
		if e != nil {
			t.Fatal(e)
		}
		keys := filepath.Join(o.KeysParent, prepared.Name)
		raw, e := readPrivate(filepath.Join(o.CopyParent, prepared.Name, "manifest.json"), backupManifestLimit)
		if e != nil {
			t.Fatal(e)
		}
		key, e := backupKey(keys)
		if e != nil {
			t.Fatal(e)
		}
		bundle, e := loadBackupKeys(context.Background(), keys)
		if e != nil {
			t.Fatal(e)
		}
		m, _, e := decodeBackupManifest(raw, key, bundle.Site)
		clear(key[:])
		if e != nil {
			t.Fatal(e)
		}
		roots = append(roots, partialSweepRoot(t, o.WorkParent, name, keys, replayCleanupPlan{Backup: m, BackupSHA: sha256.Sum256(raw)}))
	}
	return r, o, roots
}
func TestOnlineReplayCrossPairPaginationAndBusy(t *testing.T) {
	r, o, roots := onlineReplayFixture(t)
	preview, e := SweepOnlineBackupLifecycle(context.Background(), o, "", "", 1, false)
	if e != nil || preview.Replay == nil || len(preview.Replay.Items) != 1 || preview.Replay.Items[0].Status != "verified" || !preview.Replay.More || !preview.ReplayPending || len(preview.Items) != 0 {
		t.Fatal(preview, e)
	}
	first, e := SweepOnlineBackupLifecycle(context.Background(), o, "", "", 1, true)
	if e != nil || first.Replay.Items[0].Status != "reclaimed" || !first.ReplayPending || len(first.Items) != 0 {
		t.Fatal(first, e)
	}
	if _, e = os.Lstat(roots[0]); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("first root retained", e)
	}
	lock, e := platform.Lock(roots[1])
	if e != nil {
		t.Fatal(e)
	}
	stop := errors.New("stop after busy replay")
	e = r.RunOnlineBackupMaintenance(context.Background(), o, OnlineBackupSiteOptions{}, func(report BackupPreparationMaintenanceReport) error {
		if report.Status != "deferred_busy" || report.Preparation != nil || report.Cleanup == nil || report.Cleanup.Replay == nil || report.Cleanup.Replay.Busy != 1 {
			t.Error("busy replay created output", report)
		}
		return stop
	})
	if !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	last, e := SweepOnlineBackupLifecycle(context.Background(), o, "", first.Replay.Next, 128, true)
	if e != nil || last.ReplayPending || last.Replay.Items[0].Status != "reclaimed" || len(last.Items) != 2 {
		t.Fatal(last, e)
	}
	for _, item := range last.Items {
		if item.Status != "retained" {
			t.Fatal("unexpired pair removed", item)
		}
	}
	for _, root := range roots {
		if _, e = os.Lstat(root); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("root remains", e)
		}
	}
}
func TestOnlineReplayUnknownAndParentExclusion(t *testing.T) {
	_, o, roots := onlineReplayFixture(t)
	unknown := filepath.Join(roots[0], "unknown")
	if e := writeNew(unknown, []byte("retain")); e != nil {
		t.Fatal(e)
	}
	report, e := SweepOnlineBackups(context.Background(), o, "", 128, true)
	if !errors.Is(e, ErrReplaySweepRejected) || report.Replay == nil || report.Replay.Rejected != 1 || len(report.Items) != 0 {
		t.Fatal(report, e)
	}
	if _, e = os.Lstat(unknown); e != nil {
		t.Fatal("unknown removed", e)
	}
	names, e := boundedBackupNames(context.Background(), o.KeysParent, "", validBackupSweepName)
	if e != nil || len(names) != 2 {
		t.Fatal("rejected work lost keys", names, e)
	}
	if e = os.Remove(unknown); e != nil {
		t.Fatal(e)
	}
	lock, e := platform.Lock(o.WorkParent)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = SweepOnlineBackups(context.Background(), o, "", 128, true); e == nil {
		t.Fatal("work parent exclusion missing")
	}
	if _, e = VerifyBackupReplay(context.Background(), filepath.Join(o.CopyParent, names[0]), filepath.Join(o.KeysParent, names[0]), o.WorkParent); e == nil {
		t.Fatal("verification ignored work parent exclusion")
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	report, e = SweepOnlineBackups(context.Background(), o, "", 128, true)
	if e != nil || report.ReplayPending || report.Replay.Items[0].Status != "reclaimed" {
		t.Fatal(report, e)
	}
}

func TestOnlineReplayAmbiguousBundleRetainsWork(t *testing.T) {
	_, o, roots := onlineReplayFixture(t)
	names, e := boundedBackupNames(context.Background(), o.KeysParent, "", validBackupSweepName)
	if e != nil {
		t.Fatal(e)
	}
	// 同一束の別位置への複製は、候補SHAに複数の鍵所有者を作るため自動選択しない。
	root := filepath.Join(o.KeysParent, "duplicate")
	if e = os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, "keys"), 0700); e != nil {
		t.Fatal(e)
	}
	files, _ := backupKeysInventory()
	for name := range files {
		raw, e := readPrivate(filepath.Join(o.KeysParent, names[0], name), backupKeysLimit)
		if e != nil {
			t.Fatal(e)
		}
		e = writeNew(filepath.Join(root, name), raw)
		clear(raw)
		if e != nil {
			t.Fatal(e)
		}
	}
	report, e := SweepOnlineBackups(context.Background(), o, "", 128, true)
	if !errors.Is(e, ErrReplaySweepRejected) || report.Replay == nil || report.Replay.Rejected != 1 || len(report.Items) != 0 {
		t.Fatal(report, e)
	}
	retained := 0
	for _, work := range roots {
		if _, e = os.Lstat(work); e == nil {
			retained++
		}
	}
	if retained != 1 {
		t.Fatal("ambiguous work did not remain", retained)
	}
}
