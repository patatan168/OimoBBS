// 定期作成の新規配置・4計画・busy延期・変更検知・未完成保持を検証する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/platform"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func preparationMaintenanceFixture(t *testing.T) (Config, BackupPreparationMaintenanceOptions) {
	t.Helper()
	cfg, _ := backupFixture(t)
	o := BackupPreparationMaintenanceOptions{CopyParent: expiredSweepParent(t), KeysParent: expiredSweepParent(t), PartialPlanParent: expiredSweepParent(t), PartialKeysPlanParent: expiredSweepParent(t), KeysPlanParent: expiredSweepParent(t), PairPlanParent: expiredSweepParent(t), WorkParent: expiredSweepParent(t), ControlParent: expiredSweepParent(t), Interval: time.Hour, Budget: time.Minute}
	o.TrustInstance = filepath.Join(expiredSweepParent(t), "trust.json")
	if _, e := ExportBackupTrust(context.Background(), cfg, o.TrustInstance); e != nil {
		t.Fatal(e)
	}
	return cfg, o
}

func TestBackupPreparationMaintenance(t *testing.T) {
	cfg, o := preparationMaintenanceFixture(t)
	ctx := context.Background()
	preview, e := PrepareNextOfflineBackup(ctx, cfg, o)
	if e != nil || preview.Status != "preview" || preview.Name != "" || preview.Preparation != nil {
		t.Fatal(preview, e)
	}
	o.Apply = true
	lock, e := platform.Lock(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	busy, e := PrepareNextOfflineBackup(ctx, cfg, o)
	if e != nil || busy.Status != "deferred_busy" || busy.Preparation == nil || busy.Preparation.Capture != nil {
		t.Fatal(busy, e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{o.CopyParent, o.KeysParent, o.PairPlanParent} {
		entries, e := os.ReadDir(p)
		if e != nil || len(entries) != 0 {
			t.Fatal(p, entries, e)
		}
	}
	first, e := PrepareNextOfflineBackup(ctx, cfg, o)
	if e != nil || first.Status != "completed" || !first.Preparation.Complete || first.Preparation.PairPlan.RelatedPlanCount == nil || *first.Preparation.PairPlan.RelatedPlanCount != 3 || !first.Preparation.Replay.Replayed {
		t.Fatal(first, e)
	}
	second, e := PrepareNextOfflineBackup(ctx, cfg, o)
	if e != nil || second.Name == first.Name || !second.Preparation.Complete {
		t.Fatal(second, e)
	}
	pairs, e := SweepBackupPairs(ctx, o.CopyParent, o.KeysParent, o.PairPlanParent, o.TrustInstance, "", 16, true)
	if e != nil || len(pairs.Items) != 2 || pairs.Items[0].Status != "retained" {
		t.Fatal(pairs, e)
	}
	runCtx, cancel := context.WithCancel(ctx)
	reports := []BackupPreparationMaintenanceReport{}
	e = runBackupPreparationMaintenance(runCtx, cfg, o, func(r BackupPreparationMaintenanceReport) error {
		reports = append(reports, r)
		if e := RunBackupPreparationMaintenance(ctx, cfg, o, func(BackupPreparationMaintenanceReport) error { return nil }); e == nil {
			t.Fatal("duplicate watch")
		}
		if _, e := PrepareNextOfflineBackup(ctx, cfg, o); e == nil {
			t.Fatal("concurrent next")
		}
		return nil
	}, func(context.Context, time.Duration) error { cancel(); return runCtx.Err() }, prepareNextOfflineBackup)
	if !errors.Is(e, context.Canceled) || len(reports) != 1 || !reports[0].Preparation.Complete {
		t.Fatal(reports, e)
	}
}

func TestBackupPreparationMaintenanceBoundaries(t *testing.T) {
	cfg, o := preparationMaintenanceFixture(t)
	ctx := context.Background()
	stop := errors.New("writer stop")
	passes := 0
	o.Apply = true
	e := runBackupPreparationMaintenance(ctx, cfg, o, func(r BackupPreparationMaintenanceReport) error {
		passes++
		if passes == 3 {
			return stop
		}
		return nil
	}, func(context.Context, time.Duration) error { return nil }, func(context.Context, Config, BackupPreparationMaintenanceOptions) (BackupPreparationMaintenanceReport, error) {
		if passes == 0 {
			return BackupPreparationMaintenanceReport{Status: "deferred_busy"}, nil
		}
		if passes == 1 {
			return BackupPreparationMaintenanceReport{Status: "budget_exhausted"}, context.DeadlineExceeded
		}
		return BackupPreparationMaintenanceReport{Status: "completed"}, nil
	})
	if !errors.Is(e, stop) || passes != 3 {
		t.Fatal(passes, e)
	}
	for _, kind := range []string{"source", "copies", "keys", "partial", "partial-keys", "complete", "pair", "work", "control", "trust"} {
		t.Run(kind, func(t *testing.T) {
			cfg, o := preparationMaintenanceFixture(t)
			count := 0
			e := runBackupPreparationMaintenance(ctx, cfg, o, func(BackupPreparationMaintenanceReport) error { count++; return nil }, func(context.Context, time.Duration) error {
				if kind == "trust" {
					raw, e := os.ReadFile(o.TrustInstance)
					if e != nil {
						return e
					}
					return os.WriteFile(o.TrustInstance, append(raw, '\n'), 0600)
				}
				path := map[string]string{"source": cfg.DataDir, "copies": o.CopyParent, "keys": o.KeysParent, "partial": o.PartialPlanParent, "partial-keys": o.PartialKeysPlanParent, "complete": o.KeysPlanParent, "pair": o.PairPlanParent, "work": o.WorkParent, "control": o.ControlParent}[kind]
				if e := os.Rename(path, path+"-old"); e != nil {
					return e
				}
				return os.Mkdir(path, 0700)
			}, prepareNextOfflineBackup)
			if e == nil || count != 1 {
				t.Fatal(count, e)
			}
		})
	}
}

func TestBackupPreparationMaintenancePreflight(t *testing.T) {
	cfg, o := preparationMaintenanceFixture(t)
	ctx := context.Background()
	for _, change := range []func(*BackupPreparationMaintenanceOptions){
		func(v *BackupPreparationMaintenanceOptions) { v.CopyParent = cfg.DataDir },
		func(v *BackupPreparationMaintenanceOptions) { v.KeysParent = v.CopyParent },
		func(v *BackupPreparationMaintenanceOptions) { v.PairPlanParent = filepath.Join(v.CopyParent, "nested") },
		func(v *BackupPreparationMaintenanceOptions) { v.Budget = 0 },
		func(v *BackupPreparationMaintenanceOptions) { v.Budget = time.Hour + time.Nanosecond },
	} {
		invalid := o
		change(&invalid)
		if _, e := PrepareNextOfflineBackup(ctx, cfg, invalid); e == nil {
			t.Fatal("invalid paths/budget accepted")
		}
	}
	for _, interval := range []time.Duration{0, 59 * time.Minute, 25 * time.Hour} {
		invalid := o
		invalid.Interval = interval
		if e := RunBackupPreparationMaintenance(ctx, cfg, invalid, func(BackupPreparationMaintenanceReport) error { return nil }); e == nil {
			t.Fatal(interval)
		}
	}
	if e := RunBackupPreparationMaintenance(ctx, cfg, o, nil); e == nil {
		t.Fatal("nil writer")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := PrepareNextOfflineBackup(canceled, cfg, o); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}

	expired, expireCancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	result, e := prepareNextOfflineBackup(expired, cfg, o)
	expireCancel()
	if !errors.Is(e, context.DeadlineExceeded) || result.Status != "budget_exhausted" {
		t.Fatal(result, e)
	}
	for i := 0; i < 4095; i++ {
		if e := os.WriteFile(filepath.Join(o.CopyParent, ".reserved-"+strconv.Itoa(i)), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := PrepareNextOfflineBackup(ctx, cfg, o); e == nil {
		t.Fatal("unbounded parent accepted")
	}
	if onlyPreparationBusy(errors.Join(syscall.EWOULDBLOCK, errors.New("close failure"))) {
		t.Fatal("close error hidden")
	}
	if !onlyPreparationBusy(errors.Join(syscall.EWOULDBLOCK)) {
		t.Fatal("busy join rejected")
	}
}
