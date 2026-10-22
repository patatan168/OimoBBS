// 完成鍵束の回収計画を同じ正本排他で保存し、配置拒否/後続失敗の保持を検証する。
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

func TestBackupPreparationCompleteKeysPlan(t *testing.T) {
	cfg, output := backupFixture(t)
	parent := filepath.Dir(output)
	trust, plan := filepath.Join(parent, "trust.json"), filepath.Join(parent, "keys-plan.json")
	if _, e := ExportBackupTrust(context.Background(), cfg, trust); e != nil {
		t.Fatal(e)
	}
	keys, work := filepath.Join(parent, "keys"), filepath.Join(parent, "work")
	if e := os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	stages := []string{}
	report, e := prepareOfflineBackupWithPlan(context.Background(), cfg, output, keys, work, &backupPartialPreparation{trust: trust, completePlan: plan}, time.Now, func(stage string) error {
		stages = append(stages, stage)
		if stage == "source_closed" {
			return os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable")
		}
		if lock, err := platform.Lock(cfg.DataDir); err == nil {
			_ = platform.Unlock(lock)
			t.Fatal("source exclusion lost")
		}
		if stage == "keys_complete" {
			if _, err := os.Stat(plan); !os.IsNotExist(err) {
				t.Fatal("plan preceded complete keys", err)
			}
		}
		if stage == "keys_plan_synced" {
			info, err := os.Stat(plan)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal(err)
			}
		}
		return nil
	})
	if e != nil || !report.Complete || report.KeysPlanned == nil || !*report.KeysPlanned || report.KeysPlan == nil || !report.KeysPlan.Planned || report.PartialPlanned != nil || report.KeysPartialPlanned != nil || !report.Replay.Replayed || report.KeysPlan.Backup.ID != report.Capture.ID {
		t.Fatal(report, e)
	}
	if !reflect.DeepEqual(stages, []string{"capture_complete", "keys_complete", "keys_plan_synced", "source_closed"}) {
		t.Fatal(stages)
	}
	retained, e := ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true)
	if e != nil || retained.Applied || retained.Expired || retained.RestoreReady {
		t.Fatal(retained, e)
	}
	if e = os.Rename(cfg.DataDir+"-unavailable", cfg.DataDir); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{plan, trust, filepath.Join(work, "plan"), filepath.Join(parent, "rejected-body", "plan"), filepath.Join(parent, "rejected-keys", "plan")} {
		rejected, err := PrepareOfflineBackupPlanned(context.Background(), cfg, filepath.Join(parent, "rejected-body"), filepath.Join(parent, "rejected-keys"), work, BackupPreparationPlans{TrustInstance: trust, KeysPlan: bad})
		if err == nil || rejected.Phase != "preflight" || rejected.Complete || rejected.KeysPlanned == nil || *rejected.KeysPlanned || rejected.Capture != nil {
			t.Fatal(rejected, err)
		}
		if _, err = os.Stat(filepath.Join(parent, "rejected-body")); !os.IsNotExist(err) {
			t.Fatal("invalid plan created body", err)
		}
		if _, err = json.Marshal(rejected); err != nil {
			t.Fatal(err)
		}
	}
	allBody, allKeys := filepath.Join(parent, "all-body"), filepath.Join(parent, "all-keys")
	bodyPlan, keyPartial, complete := filepath.Join(parent, "body-plan"), filepath.Join(parent, "partial-key-plan"), filepath.Join(parent, "complete-key-plan")
	all, e := PrepareOfflineBackupPlanned(context.Background(), cfg, allBody, allKeys, work, BackupPreparationPlans{TrustInstance: trust, PartialPlan: bodyPlan, PartialKeysPlan: keyPartial, KeysPlan: complete})
	if e != nil || !all.Complete || !*all.PartialPlanned || !*all.KeysPartialPlanned || !*all.KeysPlanned || !all.KeysPlan.Planned || !all.Replay.Replayed {
		t.Fatal(all, e)
	}
	// 同期済み計画の後の中断は完成コピー/鍵束/計画を保持する。
	stop := errors.New("stop after completed key plan sync")
	stoppedPlan := filepath.Join(parent, "stopped-plan")
	stopped, e := prepareOfflineBackupWithPlan(context.Background(), cfg, filepath.Join(parent, "stopped-body"), filepath.Join(parent, "stopped-keys"), work, &backupPartialPreparation{trust: trust, completePlan: stoppedPlan}, time.Now, func(stage string) error {
		if stage == "keys_plan_synced" {
			return stop
		}
		return nil
	})
	if !errors.Is(e, stop) || stopped.Complete || stopped.Phase != "keys_plan" || !*stopped.KeysPlanned || !stopped.Keys.Verified || stopped.Replay != nil {
		t.Fatal(stopped, e)
	}
	if _, e = json.Marshal(stopped); e != nil {
		t.Fatal(e)
	}
	// 鍵完成後に計画先が埋まっても上書きせず、完成出力を保持して失敗JSONを返す。
	blockedPlan := filepath.Join(parent, "blocked-plan")
	blocked, e := prepareOfflineBackupWithPlan(context.Background(), cfg, filepath.Join(parent, "blocked-body"), filepath.Join(parent, "blocked-keys"), work, &backupPartialPreparation{trust: trust, completePlan: blockedPlan}, time.Now, func(stage string) error {
		if stage == "keys_complete" {
			return os.WriteFile(blockedPlan, []byte("occupied"), 0600)
		}
		return nil
	})
	if e == nil || blocked.Complete || blocked.Phase != "keys_plan" || *blocked.KeysPlanned || !blocked.Keys.Verified || blocked.Replay != nil {
		t.Fatal(blocked, e)
	}
	if _, e = json.Marshal(blocked); e != nil {
		t.Fatal(e)
	}
	if raw, err := os.ReadFile(blockedPlan); err != nil || string(raw) != "occupied" {
		t.Fatal("existing plan overwritten", err)
	}
	if _, e = os.Stat(filepath.Join(parent, "blocked-body", "manifest.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(parent, "blocked-keys", "bundle.json")); e != nil {
		t.Fatal(e)
	}
}
