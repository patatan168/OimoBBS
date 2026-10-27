// 一括作成でも本文より先に計画を保存し、正本喪失後の途中回収へ接続する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/platform"
)

func TestPlannedBackupPreparation(t *testing.T) {
	cfg, output := backupFixture(t)
	parent := filepath.Dir(output)
	trust := filepath.Join(parent, "trust.json")
	work := filepath.Join(parent, "work")
	if e := os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := ExportBackupTrust(context.Background(), cfg, trust); e != nil {
		t.Fatal(e)
	}
	keys, plan := filepath.Join(parent, "keys"), filepath.Join(parent, "plan.json")
	stages := []string{}
	report, e := prepareOfflineBackupWithPlan(context.Background(), cfg, output, keys, work, &backupPartialPreparation{trust: trust, plan: plan}, time.Now, func(stage string) error {
		stages = append(stages, stage)
		if stage == "source_closed" {
			return os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable")
		}
		if lock, err := platform.Lock(cfg.DataDir); err == nil {
			_ = platform.Unlock(lock)
			t.Fatal("source exclusion lost")
		}
		if stage == "partial_plan_synced" {
			entries, err := os.ReadDir(output)
			if err != nil || len(entries) != 0 {
				t.Fatal("payload preceded plan", entries, err)
			}
			info, err := os.Stat(plan)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("plan missing/private mode", err)
			}
		}
		return nil
	})
	if e != nil || !report.Complete || report.PartialPlanned == nil || !*report.PartialPlanned || report.RestoreReady || report.Capture.ID != report.Keys.ID || report.Keys.ID != report.Replay.ID || !report.Replay.Replayed {
		t.Fatal(report, e)
	}
	if !reflect.DeepEqual(stages, []string{"partial_plan_synced", "capture_complete", "keys_complete", "source_closed"}) {
		t.Fatal(stages)
	}
	if _, e = ReclaimPartialBackup(context.Background(), output, trust, plan, true); e == nil {
		t.Fatal("completed body reclaimed")
	}
	if e = os.Rename(cfg.DataDir+"-unavailable", cfg.DataDir); e != nil {
		t.Fatal(e)
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}

	// 全配置と既存計画をコピー前に拒否する。
	for i, partial := range []backupPartialPreparation{{trust: trust}, {plan: filepath.Join(parent, "new-plan")}, {trust: trust, plan: filepath.Join(parent, "new-keys", "plan")}, {trust: trust, plan: filepath.Join(work, "plan")}, {trust: filepath.Join(work, "trust"), plan: filepath.Join(parent, "new-plan")}, {trust: trust, plan: plan}} {
		body := filepath.Join(parent, "rejected-copy")
		rejected, err := PreparePlannedOfflineBackup(context.Background(), cfg, body, filepath.Join(parent, "new-keys"), work, partial.trust, partial.plan)
		if err == nil || rejected.Phase != "preflight" || rejected.PartialPlanned == nil || *rejected.PartialPlanned || rejected.Complete || rejected.Capture != nil || rejected.Keys != nil {
			t.Fatal(i, rejected, err)
		}
		if _, err = json.Marshal(rejected); err != nil {
			t.Fatal("failure JSON", err)
		}
		if _, err = os.Stat(body); !os.IsNotExist(err) {
			t.Fatal("preflight created body", err)
		}
	}

	// 正本解放後の取消も有効な失敗JSONを返し、完成出力を保持する。
	ctx, cancel := context.WithCancel(context.Background())
	canceledBody, canceledPlan := filepath.Join(parent, "canceled-copy"), filepath.Join(parent, "canceled-plan.json")
	canceled, err := prepareOfflineBackupWithPlan(ctx, cfg, canceledBody, filepath.Join(parent, "canceled-keys"), work, &backupPartialPreparation{trust: trust, plan: canceledPlan}, time.Now, func(stage string) error {
		if stage == "source_closed" {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || canceled.Complete || canceled.Phase != "replay" || !*canceled.PartialPlanned || canceled.Replay != nil || !canceled.Capture.Verified || !canceled.Keys.Verified {
		t.Fatal(canceled, err)
	}
	if _, err = json.Marshal(canceled); err != nil {
		t.Fatal("canceled replay JSON", err)
	}
	if _, err = ReclaimPartialBackup(context.Background(), canceledBody, trust, canceledPlan, true); err == nil {
		t.Fatal("canceled replay completed body reclaimed")
	}

	// 同期済み計画直後の中断を作り、正本を退避したまま期限切れ回収する。
	interruptedBody, interruptedPlan := filepath.Join(parent, "interrupted"), filepath.Join(parent, "interrupted-plan.json")
	stop := errors.New("stop after plan sync")
	interrupted, e := prepareOfflineBackupWithPlan(context.Background(), cfg, interruptedBody, filepath.Join(parent, "interrupted-keys"), work, &backupPartialPreparation{trust: trust, plan: interruptedPlan}, func() time.Time { return time.Now().Add(-25 * time.Hour) }, func(stage string) error {
		if stage == "partial_plan_synced" {
			return stop
		}
		return nil
	})
	if !errors.Is(e, stop) || interrupted.Complete || interrupted.Phase != "capture" || !*interrupted.PartialPlanned || interrupted.Capture == nil || interrupted.Capture.Verified || interrupted.Keys != nil {
		t.Fatal(interrupted, e)
	}
	if _, e = json.Marshal(interrupted); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	reclaimed, e := ReclaimPartialBackup(context.Background(), interruptedBody, trust, interruptedPlan, true)
	if e != nil || !reclaimed.Expired || !reclaimed.Applied || reclaimed.Verified || reclaimed.RestoreReady {
		t.Fatal(reclaimed, e)
	}
	if _, e = os.Stat(interruptedBody); !os.IsNotExist(e) {
		t.Fatal("partial root retained", e)
	}
	if _, e = os.Stat(trust); e != nil {
		t.Fatal("trust removed", e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), interruptedBody, trust, interruptedPlan, true); e == nil {
		t.Fatal("retired plan reused")
	}
}
