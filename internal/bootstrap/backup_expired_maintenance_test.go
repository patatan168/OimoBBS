// 期限切れ本文の定期巡回を、注入待機による実回収・排他・中断・親差替えで検証する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/platform"
)

func TestExpiredMaintenanceReclaimAndCycle(t *testing.T) {
	cfg, output := backupFixture(t)
	copies, keys := filepath.Dir(output), expiredSweepParent(t)
	root, bundle := filepath.Join(copies, "a-expired"), filepath.Join(keys, "a-expired")
	clock := func() time.Time { return time.Now().Add(-25 * time.Hour) }
	if _, e := captureOfflineBackup(context.Background(), cfg, root, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	if _, e := exportBackupKeys(context.Background(), cfg, root, bundle, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	// 待機中に完成コピー/鍵束を追加する状況を、非対象のドット名からの移動で作る。
	fresh, freshKeys := filepath.Join(copies, ".new"), filepath.Join(keys, ".new")
	if _, e := CaptureOfflineBackup(context.Background(), cfg, fresh); e != nil {
		t.Fatal(e)
	}
	if _, e := ExportBackupKeys(context.Background(), cfg, fresh, freshKeys); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	bad := filepath.Join(copies, "b-rejected")
	if e := os.WriteFile(bad, nil, 0600); e != nil {
		t.Fatal(e)
	}
	o := BackupMaintenanceOptions{copies, keys, 1, time.Minute, 30 * time.Second, true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reports := []BackupMaintenanceReport{}
	waits := 0
	wait := func(ctx context.Context, d time.Duration) error {
		waits++
		if d != o.Interval {
			t.Fatal(d)
		}
		if waits == 2 {
			if e := os.Remove(bad); e != nil {
				t.Fatal(e)
			}
			if e := os.Rename(fresh, filepath.Join(copies, "c-fresh")); e != nil {
				t.Fatal(e)
			}
			if e := os.Rename(freshKeys, filepath.Join(keys, "c-fresh")); e != nil {
				t.Fatal(e)
			}
		}
		if waits == 4 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	emit := func(r BackupMaintenanceReport) error {
		reports = append(reports, r)
		if len(reports) == 1 {
			if e := RunBackupMaintenance(ctx, o, func(BackupMaintenanceReport) error { return nil }); e == nil {
				t.Fatal("duplicate accepted")
			}
		}
		return nil
	}
	e := runBackupMaintenance(ctx, o, emit, wait, SweepExpiredBackups)
	if !errors.Is(e, context.Canceled) || len(reports) != 4 || reports[0].Sweep.Items[0].Status != "reclaimed" || !reports[0].Sweep.More || reports[1].Status != "needs_attention" || reports[1].Sweep.Next != "b-rejected" || reports[2].Sweep.Items[0].Status != "retained" || reports[2].Sweep.Items[0].Name != "c-fresh" || reports[3].Sweep.Items[0].Status != "retained" || reports[3].Pass != 4 {
		t.Fatal(reports, e)
	}
	if _, e = os.Stat(root); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("body remains", e)
	}
	if _, e = loadBackupKeys(context.Background(), bundle); e != nil {
		t.Fatal("keys changed", e)
	}
	if _, e = os.Stat(filepath.Join(keys, ".lock")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("key parent changed", e)
	}
	lock, e := platform.Lock(copies)
	if e != nil {
		t.Fatal("lock leaked", e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
}

func TestExpiredMaintenanceBoundaries(t *testing.T) {
	o := BackupMaintenanceOptions{expiredSweepParent(t), expiredSweepParent(t), 16, time.Minute, 30 * time.Second, false}
	emit := func(BackupMaintenanceReport) error { return nil }
	for _, mutate := range []func(*BackupMaintenanceOptions){func(v *BackupMaintenanceOptions) { v.Limit = 0 }, func(v *BackupMaintenanceOptions) { v.Limit = 129 }, func(v *BackupMaintenanceOptions) { v.Interval = time.Second }, func(v *BackupMaintenanceOptions) { v.Interval = 25 * time.Hour }, func(v *BackupMaintenanceOptions) { v.Budget = 0 }, func(v *BackupMaintenanceOptions) { v.Budget = 6 * time.Minute }, func(v *BackupMaintenanceOptions) { v.KeysParent = v.CopyParent }} {
		bad := o
		mutate(&bad)
		if e := RunBackupMaintenance(context.Background(), bad, emit); e == nil {
			t.Fatal("invalid options accepted", bad)
		}
	}
	if e := RunBackupMaintenance(context.Background(), o, nil); e == nil {
		t.Fatal("nil writer accepted")
	}
	stop := errors.New("writer stopped")
	if e := RunBackupMaintenance(context.Background(), o, func(BackupMaintenanceReport) error { return stop }); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := RunBackupMaintenance(ctx, o, emit); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	// 予算超過と拒否は継続し、完了位置を引き継ぐ。全ページ後は先頭へ戻る。
	calls := 0
	statuses := []string{}
	sweep := func(ctx context.Context, copies, keys, after string, limit int, apply bool) (BackupSweepReport, error) {
		calls++
		if copies != o.CopyParent || keys != o.KeysParent || limit != o.Limit || apply || ctx.Err() != nil {
			t.Fatal("arguments", calls)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("no budget")
		}
		switch calls {
		case 1:
			if after != "" {
				t.Fatal(after)
			}
			return BackupSweepReport{Next: "a", More: true}, context.DeadlineExceeded
		case 2:
			if after != "a" {
				t.Fatal(after)
			}
			return BackupSweepReport{Next: "b", Rejected: 1}, ErrBackupSweepRejected
		default:
			if after != "" {
				t.Fatal(after)
			}
			return BackupSweepReport{}, stop
		}
	}
	e := runBackupMaintenance(context.Background(), o, func(r BackupMaintenanceReport) error { statuses = append(statuses, r.Status); return nil }, func(context.Context, time.Duration) error { return nil }, sweep)
	if !errors.Is(e, stop) || len(statuses) != 3 || statuses[0] != "budget_exhausted" || statuses[1] != "needs_attention" || statuses[2] != "failed" {
		t.Fatal(statuses, e)
	}
}

func TestExpiredMaintenanceParentReplacement(t *testing.T) {
	for _, which := range []string{"copies", "keys"} {
		t.Run(which, func(t *testing.T) {
			o := BackupMaintenanceOptions{expiredSweepParent(t), expiredSweepParent(t), 16, time.Minute, 30 * time.Second, false}
			reports := 0
			e := runBackupMaintenance(context.Background(), o, func(BackupMaintenanceReport) error { reports++; return nil }, func(context.Context, time.Duration) error {
				parent := o.CopyParent
				if which == "keys" {
					parent = o.KeysParent
				}
				if e := os.Rename(parent, parent+"-moved"); e != nil {
					return e
				}
				return os.Mkdir(parent, 0700)
			}, SweepExpiredBackups)
			if e == nil || reports != 1 {
				t.Fatal("replacement accepted", reports, e)
			}
		})
	}
}
