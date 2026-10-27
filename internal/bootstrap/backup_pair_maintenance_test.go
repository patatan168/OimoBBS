// 両親列挙によるペア回収再開・ページ・拒否保持・定期排他を検証する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupPairSweepAndMaintenance(t *testing.T) {
	cfg, _ := backupFixture(t)
	ctx := context.Background()
	bodies, keys, plans, controls := expiredSweepParent(t), expiredSweepParent(t), expiredSweepParent(t), expiredSweepParent(t)
	trust := filepath.Join(controls, "trust.json")
	if _, e := ExportBackupTrust(ctx, cfg, trust); e != nil {
		t.Fatal(e)
	}
	past := time.Now().Add(-25 * time.Hour)
	old := func() time.Time { return past }
	makePair := func(name string, clock func() time.Time) {
		t.Helper()
		b, k, p := filepath.Join(bodies, name), filepath.Join(keys, name), filepath.Join(plans, name+".json")
		if _, e := captureOfflineBackup(ctx, cfg, b, clock, func(string) {}); e != nil {
			t.Fatal(e)
		}
		if _, e := exportBackupKeys(ctx, cfg, b, k, clock, func(string) {}); e != nil {
			t.Fatal(e)
		}
		if _, e := planBackupPairReclamation(ctx, cfg, b, k, trust, p, clock); e != nil {
			t.Fatal(e)
		}
	}
	makePair("a-expired", old)
	makePair("b-fresh", time.Now)
	makePair("c-resume", old)
	stop := errors.New("stop after body")
	if _, e := reclaimBackupPair(ctx, filepath.Join(bodies, "c-resume"), filepath.Join(keys, "c-resume"), trust, filepath.Join(plans, "c-resume.json"), true, time.Now, func(stage string) error {
		if stage == "pair:body_removed" {
			return stop
		}
		return nil
	}); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(bodies, "d-orphan"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(cfg.DataDir, cfg.DataDir+"-offline"); e != nil {
		t.Fatal(e)
	}
	preview, e := SweepBackupPairs(ctx, bodies, keys, plans, trust, "", 128, false)
	if !errors.Is(e, ErrBackupSweepRejected) || len(preview.Items) != 4 || preview.Items[0].Status != "expired" || preview.Items[1].Status != "retained" || !preview.Items[2].Pair.BodyRemoved || preview.Items[3].Status != "rejected" {
		t.Fatal(preview, e)
	}
	interruptedCtx, interrupt := context.WithCancel(ctx)
	interrupted, e := sweepBackupPairs(interruptedCtx, bodies, keys, plans, trust, "", 1, true, func() time.Time { interrupt(); return time.Now() })
	interrupt()
	if !errors.Is(e, context.Canceled) || !interrupted.More || interrupted.Next != "" || len(interrupted.Items) != 1 || interrupted.Items[0].Status != "interrupted" || interrupted.Items[0].Pair == nil {
		t.Fatal(interrupted, e)
	}
	if _, e = os.Stat(filepath.Join(bodies, "a-expired", "manifest.json")); e != nil {
		t.Fatal("interrupted item changed", e)
	}
	o := BackupPairMaintenanceOptions{bodies, keys, plans, trust, 1, time.Minute, 30 * time.Second, true}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	reports := []BackupPairMaintenanceReport{}
	e = runBackupPairMaintenance(runCtx, o, func(r BackupPairMaintenanceReport) error {
		reports = append(reports, r)
		if len(reports) == 1 {
			if _, e := SweepBackupPairs(ctx, bodies, keys, plans, trust, "", 16, true); e == nil {
				t.Fatal("concurrent sweep accepted")
			}
			if e := RunBackupPairMaintenance(ctx, o, func(BackupPairMaintenanceReport) error { return nil }); e == nil {
				t.Fatal("duplicate watch accepted")
			}
			if _, e := SweepPartialBackups(ctx, "keys", keys, plans, trust, "", 16, true); e == nil {
				t.Fatal("keys parent lock missing")
			}
		}
		return nil
	}, func(context.Context, time.Duration) error {
		if len(reports) == 4 {
			cancel()
			return runCtx.Err()
		}
		return nil
	}, sweepBackupPairs)
	if !errors.Is(e, context.Canceled) || len(reports) != 4 {
		t.Fatal(reports, e)
	}
	want := []string{"reclaimed", "retained", "reclaimed", "rejected"}
	for i, r := range reports {
		if len(r.Sweep.Items) != 1 || r.Sweep.Items[0].Status != want[i] {
			t.Fatal(i, r)
		}
	}
	if _, e := os.Stat(filepath.Join(keys, "c-resume")); !os.IsNotExist(e) {
		t.Fatal("resume keys remain", e)
	}
	if _, e := os.Stat(filepath.Join(bodies, "d-orphan")); e != nil {
		t.Fatal("orphan removed", e)
	}
	if _, e := VerifyBackupWithKeys(ctx, filepath.Join(bodies, "b-fresh"), filepath.Join(keys, "b-fresh")); e != nil {
		t.Fatal("fresh changed", e)
	}
}

func pairMaintenanceTestOptions(t *testing.T) BackupPairMaintenanceOptions {
	t.Helper()
	base := plannedKeysTestOptions(t)
	return BackupPairMaintenanceOptions{expiredSweepParent(t), base.KeysParent, base.PlanParent, base.TrustInstance, 1, time.Minute, time.Second, false}
}

func TestBackupPairMaintenanceBoundaries(t *testing.T) {
	ctx := context.Background()
	stop := errors.New("writer stop")
	o := pairMaintenanceTestOptions(t)
	calls := 0
	afters := []string{}
	statuses := []string{}
	e := runBackupPairMaintenance(ctx, o, func(r BackupPairMaintenanceReport) error {
		statuses = append(statuses, r.Status)
		if len(statuses) == 4 {
			return stop
		}
		return nil
	}, func(context.Context, time.Duration) error { return nil }, func(_ context.Context, _, _, _, _, after string, _ int, _ bool, _ func() time.Time) (BackupPairSweepReport, error) {
		calls++
		afters = append(afters, after)
		if calls == 1 {
			return BackupPairSweepReport{Items: []BackupPairSweepItem{}, Next: "a", More: true}, nil
		}
		if calls == 2 {
			return BackupPairSweepReport{Items: []BackupPairSweepItem{{Name: "b", Status: "budget_exhausted"}}, Next: "a", More: true}, context.DeadlineExceeded
		}
		return BackupPairSweepReport{Items: []BackupPairSweepItem{}, Next: "b"}, nil
	})
	if !errors.Is(e, stop) || len(afters) != 4 || afters[0] != "" || afters[1] != "a" || afters[2] != "a" || afters[3] != "" || statuses[1] != "budget_exhausted" {
		t.Fatal(afters, statuses, e)
	}
	for _, kind := range []string{"body", "keys", "plans", "trust"} {
		o := pairMaintenanceTestOptions(t)
		emitted := 0
		e = runBackupPairMaintenance(ctx, o, func(BackupPairMaintenanceReport) error { emitted++; return nil }, func(context.Context, time.Duration) error {
			if kind == "trust" {
				raw, e := os.ReadFile(o.TrustInstance)
				if e != nil {
					return e
				}
				return os.WriteFile(o.TrustInstance, append(raw, '\n'), 0600)
			}
			path := map[string]string{"body": o.CopyParent, "keys": o.KeysParent, "plans": o.PlanParent}[kind]
			if e := os.Rename(path, path+"-old"); e != nil {
				return e
			}
			return os.Mkdir(path, 0700)
		}, sweepBackupPairs)
		if e == nil || emitted != 1 {
			t.Fatal(kind, emitted, e)
		}
	}
	o = pairMaintenanceTestOptions(t)
	if e = RunBackupPairMaintenance(ctx, o, nil); e == nil {
		t.Fatal("nil writer")
	}
	for _, after := range []string{"..", ".hidden", "a/b"} {
		if _, e := SweepBackupPairs(ctx, o.CopyParent, o.KeysParent, o.PlanParent, o.TrustInstance, after, 16, false); e == nil {
			t.Fatal(after)
		}
	}
	for _, limit := range []int{0, 129} {
		if _, e := SweepBackupPairs(ctx, o.CopyParent, o.KeysParent, o.PlanParent, o.TrustInstance, "", limit, false); e == nil {
			t.Fatal(limit)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := SweepBackupPairs(canceled, o.CopyParent, o.KeysParent, o.PlanParent, o.TrustInstance, "", 16, false); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
