// 署名付き鍵束巡回の実回収、途中再開、使用済み保持、周期/排他/信頼根固定を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
)

func TestPlannedKeysSweepAndMaintenance(t *testing.T) {
	cfg, backup := backupFixture(t)
	keys, plans, controls := expiredSweepParent(t), expiredSweepParent(t), expiredSweepParent(t)
	trust := filepath.Join(controls, "trust.json")
	if _, e := ExportBackupTrust(context.Background(), cfg, trust); e != nil {
		t.Fatal(e)
	}
	past := time.Now().Add(-25 * time.Hour)
	old := func() time.Time { return past }
	if _, e := captureOfflineBackup(context.Background(), cfg, backup, old, func(string) {}); e != nil {
		t.Fatal(e)
	}
	stop := errors.New("boundary stop")
	for _, name := range []string{"a-expired", "d-partial", "e-retired"} {
		root, plan := filepath.Join(keys, name), filepath.Join(plans, name+".json")
		if _, e := exportBackupKeys(context.Background(), cfg, backup, root, old, func(string) {}); e != nil {
			t.Fatal(e)
		}
		if _, e := planBackupKeysReclamation(context.Background(), cfg, root, trust, plan, old); e != nil {
			t.Fatal(e)
		}
		if name != "a-expired" {
			boundary := "backup:reclaim_manifest"
			if name == "e-retired" {
				boundary = "backup:keys_plan_retired"
			}
			if _, e := reclaimBackupKeysPlanned(context.Background(), root, trust, plan, true, time.Now, func(stage string) error {
				if stage == boundary {
					return stop
				}
				return nil
			}); !errors.Is(e, stop) {
				t.Fatal(e)
			}
		}
	}
	fresh := filepath.Join(filepath.Dir(backup), "fresh")
	if _, e := CaptureOfflineBackup(context.Background(), cfg, fresh); e != nil {
		t.Fatal(e)
	}
	freshKeys := filepath.Join(keys, "b-fresh")
	if _, e := ExportBackupKeys(context.Background(), cfg, fresh, freshKeys); e != nil {
		t.Fatal(e)
	}
	if _, e := PlanBackupKeysReclamation(context.Background(), cfg, freshKeys, trust, filepath.Join(plans, "b-fresh.json")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(keys, "c-missing"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	preview, e := SweepPlannedBackupKeys(context.Background(), keys, plans, trust, "", 128, false)
	if !errors.Is(e, ErrBackupSweepRejected) || len(preview.Items) != 5 || preview.Rejected != 2 || preview.Items[0].Status != "expired" || preview.Items[1].Status != "retained" || preview.Items[3].Status != "expired" {
		t.Fatal(preview, e)
	}
	if _, e := os.Stat(filepath.Join(keys, "a-expired", "bundle.json")); e != nil {
		t.Fatal("preview changed keys", e)
	}
	o := BackupKeysMaintenanceOptions{keys, plans, trust, 1, time.Minute, 30 * time.Second, true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reports := []BackupMaintenanceReport{}
	waits := 0
	e = runBackupKeysMaintenance(ctx, o, func(r BackupMaintenanceReport) error {
		reports = append(reports, r)
		if len(reports) == 1 {
			if _, e := SweepPlannedBackupKeys(ctx, keys, plans, trust, "", 16, true); e == nil {
				t.Fatal("parallel sweep accepted")
			}
			if e := RunBackupKeysMaintenance(ctx, o, func(BackupMaintenanceReport) error { return nil }); e == nil {
				t.Fatal("duplicate watch accepted")
			}
		}
		return nil
	}, func(ctx context.Context, interval time.Duration) error {
		waits++
		if interval != o.Interval {
			t.Fatal(interval)
		}
		if waits == 2 {
			if e := os.Mkdir(filepath.Join(keys, "f-new"), 0700); e != nil {
				t.Fatal(e)
			}
		}
		if waits == 7 {
			cancel()
			return ctx.Err()
		}
		return nil
	}, sweepPlannedBackupKeys)
	if !errors.Is(e, context.Canceled) || len(reports) != 7 {
		t.Fatal(reports, e)
	}
	want := []string{"reclaimed", "retained", "rejected", "reclaimed", "rejected", "rejected", "retained"}
	for i, r := range reports {
		if len(r.Sweep.Items) != 1 || r.Sweep.Items[0].Status != want[i] || r.Pass != domain.U64(i+1) {
			t.Fatal(i, r)
		}
	}
	if reports[5].Sweep.Items[0].Name != "f-new" || reports[5].Sweep.More || reports[6].Sweep.Items[0].Name != "b-fresh" {
		t.Fatal("cursor/new child", reports)
	}
	for _, name := range []string{"a-expired", "d-partial"} {
		if _, e := os.Stat(filepath.Join(keys, name)); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("keys remain", name, e)
		}
		raw, e := os.ReadFile(filepath.Join(plans, name+".json"))
		if e != nil {
			t.Fatal(e)
		}
		var env backupKeysPlanEnvelope
		if e = json.Unmarshal(raw, &env); e != nil || !env.Retired {
			t.Fatal("plan not retired", name, e)
		}
	}
	if _, e := os.Stat(filepath.Join(keys, "e-retired")); e != nil {
		t.Fatal("retired root removed", e)
	}
	if _, e := VerifyBackupWithKeys(context.Background(), fresh, freshKeys); e != nil {
		t.Fatal("fresh changed", e)
	}
	if _, e := os.Stat(filepath.Join(plans, ".lock")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("plan parent lock added", e)
	}
	lock, e := platform.Lock(keys)
	if e != nil {
		t.Fatal("lock leaked", e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
}

// plannedKeysTestOptions は空の巡回親と有効な公開形式の信頼根を用意する。
func plannedKeysTestOptions(t *testing.T) BackupKeysMaintenanceOptions {
	t.Helper()
	controls := expiredSweepParent(t)
	trust := filepath.Join(controls, "trust.json")
	raw, e := json.Marshal(instance{Schema: storageFormatVersion, SiteID: domain.NewID(), MasterSHA: domain.Hash{1}, SigningPublic: domain.Hash{2}})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(trust, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return BackupKeysMaintenanceOptions{expiredSweepParent(t), expiredSweepParent(t), trust, 16, time.Minute, 30 * time.Second, false}
}

func TestPlannedKeysMaintenanceBoundaries(t *testing.T) {
	o := plannedKeysTestOptions(t)
	emit := func(BackupMaintenanceReport) error { return nil }
	for _, mutate := range []func(*BackupKeysMaintenanceOptions){func(v *BackupKeysMaintenanceOptions) { v.Limit = 0 }, func(v *BackupKeysMaintenanceOptions) { v.Limit = 129 }, func(v *BackupKeysMaintenanceOptions) { v.Interval = time.Second }, func(v *BackupKeysMaintenanceOptions) { v.Interval = 25 * time.Hour }, func(v *BackupKeysMaintenanceOptions) { v.Budget = 0 }, func(v *BackupKeysMaintenanceOptions) { v.Budget = 6 * time.Minute }, func(v *BackupKeysMaintenanceOptions) { v.PlanParent = v.KeysParent }, func(v *BackupKeysMaintenanceOptions) { v.TrustInstance = filepath.Join(v.KeysParent, "trust.json") }} {
		bad := o
		mutate(&bad)
		if e := RunBackupKeysMaintenance(context.Background(), bad, emit); e == nil {
			t.Fatal("invalid options accepted", bad)
		}
	}
	if e := RunBackupKeysMaintenance(context.Background(), o, nil); e == nil {
		t.Fatal("nil writer accepted")
	}
	stop := errors.New("output stop")
	if e := RunBackupKeysMaintenance(context.Background(), o, func(BackupMaintenanceReport) error { return stop }); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := RunBackupKeysMaintenance(ctx, o, emit); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	for _, which := range []string{"keys", "plans", "trust"} {
		t.Run(which, func(t *testing.T) {
			o := plannedKeysTestOptions(t)
			reports := []BackupMaintenanceReport{}
			e := runBackupKeysMaintenance(context.Background(), o, func(r BackupMaintenanceReport) error { reports = append(reports, r); return nil }, func(context.Context, time.Duration) error {
				if which == "trust" {
					raw, e := os.ReadFile(o.TrustInstance)
					if e != nil {
						return e
					}
					return os.WriteFile(o.TrustInstance, append(raw, '\n'), 0600)
				}
				parent := o.KeysParent
				if which == "plans" {
					parent = o.PlanParent
				}
				if e := os.Rename(parent, parent+"-moved"); e != nil {
					return e
				}
				return os.Mkdir(parent, 0700)
			}, sweepPlannedBackupKeys)
			if e == nil || which != "trust" && len(reports) != 1 || which == "trust" && (len(reports) != 2 || reports[1].Status != "failed") {
				t.Fatal("replacement accepted", reports, e)
			}
		})
	}
}

func TestPlannedKeysSweepEnumerationBound(t *testing.T) {
	o := plannedKeysTestOptions(t)
	for i := 0; i < replaySweepEntryLimit; i++ {
		if _, e := os.MkdirTemp(o.KeysParent, ".hidden-"); e != nil {
			t.Fatal(e)
		}
	}
	// public sweep adds .lock, so even hidden entries exceed the pre-delete enumeration cap.
	r, e := SweepPlannedBackupKeys(context.Background(), o.KeysParent, o.PlanParent, o.TrustInstance, "", 16, true)
	if e == nil || len(r.Items) != 0 {
		t.Fatal(r, e)
	}
	for _, after := range []string{".hidden", "../escape"} {
		if _, e := SweepPlannedBackupKeys(context.Background(), o.KeysParent, o.PlanParent, o.TrustInstance, after, 16, true); e == nil {
			t.Fatal("cursor accepted", after)
		}
	}
}
