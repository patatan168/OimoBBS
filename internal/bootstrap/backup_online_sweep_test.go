// 完成直後・途中・ペア完成後の回収を、正本喪失と未知ファイルを含めて検査する。
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

func TestOnlineLifecycleReclamation(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	if _, e := r.CreateBoard(context.Background(), "lifecycle", "回収検査"); e != nil {
		t.Fatal(e)
	}
	o := BackupPreparationMaintenanceOptions{CopyParent: expiredSweepParent(t), KeysParent: expiredSweepParent(t), PartialPlanParent: expiredSweepParent(t), PartialKeysPlanParent: expiredSweepParent(t), KeysPlanParent: expiredSweepParent(t), PairPlanParent: expiredSweepParent(t), WorkParent: expiredSweepParent(t), ControlParent: expiredSweepParent(t), TrustInstance: onlineOutput(t, "trust.json"), Budget: time.Minute, Interval: time.Hour, Apply: true}
	raw, e := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeNew(o.TrustInstance, raw); e != nil {
		t.Fatal(e)
	}
	syncOnlineAudit(t, r)
	for _, name := range []string{"body-complete", "keys-complete", "partial"} {
		body, keys := filepath.Join(o.CopyParent, name), filepath.Join(o.KeysParent, name)
		bodyPlan, keyPlan := filepath.Join(o.PartialPlanParent, name+".json"), filepath.Join(o.PartialKeysPlanParent, name+".json")
		_, e = r.captureOnlineBackup(context.Background(), body, o.TrustInstance, bodyPlan, OnlineBackupSiteOptions{}, time.Now, func(stage string) error {
			if name == "partial" && stage == "online_plan_synced" {
				return context.Canceled
			}
			return nil
		})
		if name == "partial" {
			if !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
		} else if e != nil {
			t.Fatal(e)
		}
		if name == "keys-complete" {
			signer, e := r.preparePartialBackupSigner(keys, o.TrustInstance, keyPlan)
			if e != nil {
				t.Fatal(e)
			}
			_, e = r.exportBackupKeysWithSetup(context.Background(), body, keys, time.Now, func(string) {}, func(m backupKeysManifest, raw []byte) error { return signer.saveKeys(context.Background(), m, raw) })
			clear(signer.key)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	prepared, e := r.PrepareNextOnlineBackup(context.Background(), o, OnlineBackupSiteOptions{})
	if e != nil || !prepared.Preparation.Complete {
		t.Fatal(prepared, e)
	}
	preview, e := SweepOnlineBackups(context.Background(), o, "", 128, false)
	if e != nil || len(preview.Items) != 4 {
		t.Fatal(preview, e)
	}
	lock, e := platform.Lock(o.CopyParent)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = SweepOnlineBackups(context.Background(), o, "", 128, true); e == nil {
		t.Fatal("concurrent root sweep")
	}
	stop := errors.New("stop after busy report")
	reported := false
	e = r.RunOnlineBackupMaintenance(context.Background(), o, OnlineBackupSiteOptions{}, func(report BackupPreparationMaintenanceReport) error {
		reported = true
		if report.Status != "deferred_busy" || report.Preparation != nil || report.Name != "" {
			t.Error("busy cleanup created output", report)
		}
		return stop
	})
	if !reported || !errors.Is(e, stop) {
		t.Fatal("busy cleanup did not defer", e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	// 正本秘密鍵が失われても、外部公開信頼根と署名計画だけで回収する。
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	moved := cfg.DataDir + "-lost"
	if e = os.Rename(cfg.DataDir, moved); e != nil {
		t.Fatal(e)
	}
	later := func() time.Time { return time.Now().Add(25 * time.Hour) }
	unknown := filepath.Join(o.CopyParent, "keys-complete", "unknown")
	if e = writeNew(unknown, []byte("preserve")); e != nil {
		t.Fatal(e)
	}
	report, e := sweepOnlineBackups(context.Background(), o, "", 128, true, later)
	if !errors.Is(e, ErrBackupSweepRejected) || report.Rejected != 1 {
		t.Fatal(report, e)
	}
	if _, e = os.Lstat(unknown); e != nil {
		t.Fatal("unknown removed", e)
	}
	if _, e = os.Lstat(filepath.Join(o.KeysParent, "keys-complete", "bundle.json")); e != nil {
		t.Fatal("keys removed before rejected body", e)
	}
	if e = os.Remove(unknown); e != nil {
		t.Fatal(e)
	}
	report, e = sweepOnlineBackups(context.Background(), o, "", 128, true, later)
	if e != nil || len(report.Items) != 1 || report.Items[0].Status != "reclaimed" {
		t.Fatal(report, e)
	}
	for _, p := range []string{o.CopyParent, o.KeysParent} {
		names, e := boundedBackupNames(context.Background(), p, "", validBackupSweepName)
		if e != nil || len(names) != 0 {
			t.Fatal(names, e)
		}
	}
}
