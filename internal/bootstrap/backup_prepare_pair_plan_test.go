// 完成ペア計画の一括保存・親/正本排他・失敗保持・計画なしJSON互換を検証する。
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

func TestBackupPreparationPairPlan(t *testing.T) {
	cfg, body := backupFixture(t)
	ctx := context.Background()
	parent := filepath.Dir(body)
	keys, work, trust, plan := filepath.Join(parent, "keys"), filepath.Join(parent, "work"), filepath.Join(parent, "trust.json"), filepath.Join(parent, "pair.json")
	if e := os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := ExportBackupTrust(ctx, cfg, trust); e != nil {
		t.Fatal(e)
	}
	keyParent := filepath.Join(parent, "key-parent")
	if e := os.Mkdir(keyParent, 0700); e != nil {
		t.Fatal(e)
	}
	keys = filepath.Join(keyParent, "keys")
	stages := []string{}
	report, e := prepareOfflineBackupWithPlan(ctx, cfg, body, keys, work, &backupPartialPreparation{trust: trust, pairPlan: plan}, time.Now, func(stage string) error {
		stages = append(stages, stage)
		if lock, e := platform.Lock(parent); e == nil {
			_ = platform.Unlock(lock)
			t.Fatal("parent exclusion lost")
		}
		if lock, e := platform.Lock(keyParent); e == nil {
			_ = platform.Unlock(lock)
			t.Fatal("key parent exclusion lost")
		}
		if stage == "source_closed" {
			return os.Rename(cfg.DataDir, cfg.DataDir+"-offline")
		}
		if lock, e := platform.Lock(cfg.DataDir); e == nil {
			_ = platform.Unlock(lock)
			t.Fatal("source exclusion lost")
		}
		if stage == "keys_complete" {
			if _, e := os.Stat(plan); !os.IsNotExist(e) {
				t.Fatal("pair plan preceded completed keys", e)
			}
		}
		return nil
	})
	if e != nil || !report.Complete || report.PairPlanned == nil || !*report.PairPlanned || report.PairPlan == nil || !report.PairPlan.Planned || report.PartialPlanned != nil || report.KeysPlanned != nil || report.PairPlan.Body.ID != report.Capture.ID || report.PairPlan.Keys.ID != report.Keys.ID || !report.Replay.Replayed {
		t.Fatal(report, e)
	}
	if !reflect.DeepEqual(stages, []string{"capture_complete", "keys_complete", "pair_plan_synced", "source_closed"}) {
		t.Fatal(stages)
	}
	retained, e := ReclaimBackupPair(ctx, body, keys, trust, plan, true)
	if e != nil || retained.Applied || retained.Expired {
		t.Fatal(retained, e)
	}
	if e = os.Rename(cfg.DataDir+"-offline", cfg.DataDir); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{plan, trust, filepath.Join(work, "plan"), filepath.Join(parent, "bad-body", "plan"), filepath.Join(parent, "bad-keys", "plan")} {
		r, e := PrepareOfflineBackupPlanned(ctx, cfg, filepath.Join(parent, "bad-body"), filepath.Join(parent, "bad-keys"), work, BackupPreparationPlans{TrustInstance: trust, PairPlan: bad})
		if e == nil || r.Phase != "preflight" || r.Complete || r.Capture != nil || r.PairPlanned == nil || *r.PairPlanned {
			t.Fatal(r, e)
		}
		if _, e = os.Stat(filepath.Join(parent, "bad-body")); !os.IsNotExist(e) {
			t.Fatal("preflight created body", e)
		}
		if _, e = json.Marshal(r); e != nil {
			t.Fatal(e)
		}
	}
	for _, kind := range []string{"stop", "occupied", "all"} {
		b, k, p := filepath.Join(parent, kind+"-body"), filepath.Join(parent, kind+"-keys"), filepath.Join(parent, kind+"-pair.json")
		opts := &backupPartialPreparation{trust: trust, pairPlan: p}
		if kind == "all" {
			opts.plan = filepath.Join(parent, "partial-body.json")
			opts.keysPlan = filepath.Join(parent, "partial-keys.json")
			opts.completePlan = filepath.Join(parent, "complete-keys.json")
		}
		stop := errors.New("stop after pair plan sync")
		r, e := prepareOfflineBackupWithPlan(ctx, cfg, b, k, work, opts, time.Now, func(stage string) error {
			if kind == "stop" && stage == "pair_plan_synced" {
				return stop
			}
			if kind == "occupied" && stage == "keys_complete" {
				return os.WriteFile(p, []byte("occupied"), 0600)
			}
			return nil
		})
		if kind == "all" {
			if e != nil || !r.Complete || !*r.PairPlanned || !*r.KeysPlanned || !*r.PartialPlanned || !*r.KeysPartialPlanned {
				t.Fatal(r, e)
			}
			continue
		}
		if e == nil || r.Complete || r.Phase != "pair_plan" || r.Replay != nil || !r.Keys.Verified {
			t.Fatal(r, e)
		}
		if kind == "stop" && (!errors.Is(e, stop) || !*r.PairPlanned) {
			t.Fatal(r, e)
		}
		if kind == "occupied" {
			raw, e := os.ReadFile(p)
			if e != nil || string(raw) != "occupied" || *r.PairPlanned {
				t.Fatal(r, e)
			}
		}
		if _, e = os.Stat(filepath.Join(b, "manifest.json")); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Stat(filepath.Join(k, "bundle.json")); e != nil {
			t.Fatal(e)
		}
		if _, e = json.Marshal(r); e != nil {
			t.Fatal(e)
		}
	}
}
