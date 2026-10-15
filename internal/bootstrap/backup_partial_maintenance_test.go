// 用途別の部分出力巡回で期限回収・完成保護・ページ・排他・周期/信頼根固定を検証する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPartialBackupSweepAndMaintenance(t *testing.T) {
	cfg, body := backupFixture(t)
	controls := expiredSweepParent(t)
	trust := filepath.Join(controls, "trust.json")
	if _, e := ExportBackupTrust(context.Background(), cfg, trust); e != nil {
		t.Fatal(e)
	}
	oldTime := time.Now().Add(-25 * time.Hour)
	old := func() time.Time { return oldTime }
	if _, e := captureOfflineBackup(context.Background(), cfg, body, old, func(string) {}); e != nil {
		t.Fatal(e)
	}
	freshBody := filepath.Join(filepath.Dir(body), "fresh-body")
	if _, e := CaptureOfflineBackup(context.Background(), cfg, freshBody); e != nil {
		t.Fatal(e)
	}
	opts := map[string]BackupPartialMaintenanceOptions{}
	stop := errors.New("boundary stop")
	for _, kind := range []string{"body", "keys"} {
		roots, plans := expiredSweepParent(t), expiredSweepParent(t)
		opts[kind] = BackupPartialMaintenanceOptions{Kind: kind, RootParent: roots, PlanParent: plans, TrustInstance: trust, Limit: 1, Interval: time.Minute, Budget: 30 * time.Second, Apply: true}
		for _, name := range []string{"a-expired", "b-fresh", "d-complete", "e-retired"} {
			root, plan := filepath.Join(roots, name), filepath.Join(plans, name+".json")
			ctx, cancel := context.WithCancel(context.Background())
			clock := old
			input := body
			if name == "b-fresh" {
				clock = time.Now
				input = freshBody
			}
			boundary := func(stage string) {
				if name == "d-complete" {
					return
				}
				if stage == "backup:partial_plan_synced" || stage == "backup-keys:partial_plan_synced" {
					cancel()
				}
			}
			var e error
			if kind == "body" {
				_, e = capturePlannedOfflineBackup(ctx, cfg, root, trust, plan, clock, boundary)
			} else {
				_, e = exportPlannedBackupKeys(ctx, cfg, input, root, trust, plan, clock, boundary)
			}
			cancel()
			if name == "d-complete" && e != nil || name != "d-complete" && !errors.Is(e, context.Canceled) {
				t.Fatal(kind, name, e)
			}
			if name == "e-retired" {
				reclaim, _ := partialBackupReclaimer(kind)
				_, e = reclaim(context.Background(), root, trust, plan, true, time.Now, func(stage string) error {
					if stage == "backup:partial_plan_retired" || stage == "backup:partial_keys_plan_retired" {
						return stop
					}
					return nil
				})
				if !errors.Is(e, stop) {
					t.Fatal(kind, e)
				}
			}
		}
		if e := os.Mkdir(filepath.Join(roots, "c-missing"), 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"body", "keys"} {
		o := opts[kind]
		preview, e := SweepPartialBackups(context.Background(), kind, o.RootParent, o.PlanParent, trust, "", 128, false)
		if !errors.Is(e, ErrBackupSweepRejected) || len(preview.Items) != 5 || preview.Rejected != 3 || preview.Items[0].Status != "expired" || preview.Items[1].Status != "retained" {
			t.Fatal(kind, preview, e)
		}
		// 別用途の署名は同じroot/plan集合でも拒否する。
		wrong := "body"
		if kind == "body" {
			wrong = "keys"
		}
		mismatch, e := SweepPartialBackups(context.Background(), wrong, o.RootParent, o.PlanParent, trust, "", 128, true)
		if !errors.Is(e, ErrBackupSweepRejected) || mismatch.Rejected != 5 {
			t.Fatal(kind, mismatch, e)
		}
		ctx, cancel := context.WithCancel(context.Background())
		reports := []BackupMaintenanceReport{}
		waits := 0
		e = runBackupPartialMaintenance(ctx, o, func(r BackupMaintenanceReport) error {
			reports = append(reports, r)
			if len(reports) == 1 {
				if _, err := SweepPartialBackups(ctx, kind, o.RootParent, o.PlanParent, trust, "", 16, true); err == nil {
					t.Fatal("parallel partial sweep accepted")
				}
				if _, err := SweepPlannedBackupKeys(ctx, o.RootParent, o.PlanParent, trust, "", 16, true); err == nil {
					t.Fatal("parallel completed-key sweep accepted")
				}
				if err := RunBackupPartialMaintenance(ctx, o, func(BackupMaintenanceReport) error { return nil }); err == nil {
					t.Fatal("duplicate partial watch accepted")
				}
			}
			return nil
		}, func(ctx context.Context, interval time.Duration) error {
			waits++
			if interval != time.Minute {
				t.Fatal(interval)
			}
			if waits == 2 {
				if e := os.Mkdir(filepath.Join(o.RootParent, "f-new"), 0700); e != nil {
					t.Fatal(e)
				}
			}
			if waits == 7 {
				cancel()
				return ctx.Err()
			}
			return nil
		})
		cancel()
		if !errors.Is(e, context.Canceled) || len(reports) != 7 {
			t.Fatal(kind, reports, e)
		}
		want := []string{"reclaimed", "retained", "rejected", "rejected", "rejected", "rejected", "retained"}
		for i, r := range reports {
			if len(r.Sweep.Items) != 1 || r.Sweep.Items[0].Status != want[i] {
				t.Fatal(kind, i, r)
			}
			if want[i] == "rejected" && r.Status != "needs_attention" {
				t.Fatal(r)
			}
		}
		if reports[5].Sweep.Items[0].Name != "f-new" || reports[5].Sweep.More || reports[6].Sweep.Items[0].Name != "b-fresh" {
			t.Fatal("page/new child", reports)
		}
		if _, e = os.Stat(filepath.Join(o.RootParent, "a-expired")); !os.IsNotExist(e) {
			t.Fatal("expired root retained", e)
		}
		completed := "manifest.json"
		if kind == "keys" {
			completed = "bundle.json"
		}
		if _, e = os.Stat(filepath.Join(o.RootParent, "d-complete", completed)); e != nil {
			t.Fatal("completed output changed", e)
		}
		if _, e = os.Stat(filepath.Join(o.RootParent, "e-retired")); e != nil {
			t.Fatal("retired root changed", e)
		}
		if _, e = SweepPartialBackups(context.Background(), kind, o.RootParent, o.PlanParent, trust, "z", 16, true); e != nil {
			t.Fatal("lock/cursor", e)
		}
	}
}

func TestPartialBackupMaintenanceBoundaries(t *testing.T) {
	for _, kind := range []string{"body", "keys"} {
		t.Run(kind, func(t *testing.T) {
			legacy := plannedKeysTestOptions(t)
			o := BackupPartialMaintenanceOptions{Kind: kind, RootParent: legacy.KeysParent, PlanParent: legacy.PlanParent, TrustInstance: legacy.TrustInstance, Limit: 16, Interval: time.Minute, Budget: 30 * time.Second}
			emit := func(BackupMaintenanceReport) error { return nil }
			for _, mutate := range []func(*BackupPartialMaintenanceOptions){func(v *BackupPartialMaintenanceOptions) { v.Kind = "" }, func(v *BackupPartialMaintenanceOptions) { v.Kind = "completed" }, func(v *BackupPartialMaintenanceOptions) { v.Limit = 129 }, func(v *BackupPartialMaintenanceOptions) { v.Interval = time.Second }, func(v *BackupPartialMaintenanceOptions) { v.Budget = 6 * time.Minute }, func(v *BackupPartialMaintenanceOptions) { v.PlanParent = v.RootParent }} {
				bad := o
				mutate(&bad)
				if e := RunBackupPartialMaintenance(context.Background(), bad, emit); e == nil {
					t.Fatal("invalid partial options accepted", bad)
				}
			}
			if _, e := SweepPartialBackups(context.Background(), "", o.RootParent, o.PlanParent, o.TrustInstance, "", 16, true); e == nil {
				t.Fatal("missing kind accepted")
			}
			if _, e := SweepPartialBackups(context.Background(), kind, o.RootParent, o.PlanParent, o.TrustInstance, "../escape", 16, true); e == nil {
				t.Fatal("cursor accepted")
			}
			stop := errors.New("writer stop")
			if e := RunBackupPartialMaintenance(context.Background(), o, func(BackupMaintenanceReport) error { return stop }); !errors.Is(e, stop) {
				t.Fatal(e)
			}
			if e := RunBackupPartialMaintenance(context.Background(), o, nil); e == nil {
				t.Fatal("nil writer accepted")
			}
			for _, which := range []string{"root", "plans", "trust"} {
				t.Run(which, func(t *testing.T) {
					legacy := plannedKeysTestOptions(t)
					copy := o
					copy.RootParent = legacy.KeysParent
					copy.PlanParent = legacy.PlanParent
					copy.TrustInstance = legacy.TrustInstance
					reports := []BackupMaintenanceReport{}
					e := runBackupPartialMaintenance(context.Background(), copy, func(r BackupMaintenanceReport) error { reports = append(reports, r); return nil }, func(context.Context, time.Duration) error {
						if which == "trust" {
							raw, e := os.ReadFile(copy.TrustInstance)
							if e != nil {
								return e
							}
							return os.WriteFile(copy.TrustInstance, append(raw, '\n'), 0600)
						}
						parent := copy.RootParent
						if which == "plans" {
							parent = copy.PlanParent
						}
						if e := os.Rename(parent, parent+"-moved"); e != nil {
							return e
						}
						return os.Mkdir(parent, 0700)
					})
					if e == nil || which != "trust" && len(reports) != 1 || which == "trust" && (len(reports) != 2 || reports[1].Status != "failed") {
						t.Fatal("partial replacement accepted", reports, e)
					}
				})
			}
		})
	}
}
