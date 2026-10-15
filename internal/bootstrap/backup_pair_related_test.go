// 登録済み計画の一括使用済み化・全件事前照合・部分中断再開を検証する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupPairRelatedRetirement(t *testing.T) {
	cfg, body := backupFixture(t)
	parent := filepath.Dir(body)
	ctx := context.Background()
	trust, work, keys, pair := filepath.Join(parent, "trust.json"), filepath.Join(parent, "work"), filepath.Join(parent, "keys"), filepath.Join(parent, "pair.json")
	if _, e := ExportBackupTrust(ctx, cfg, trust); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	opts := BackupPreparationPlans{TrustInstance: trust, PartialPlan: filepath.Join(parent, "body-partial.json"), PartialKeysPlan: filepath.Join(parent, "keys-partial.json"), KeysPlan: filepath.Join(parent, "keys-complete.json"), PairPlan: pair}
	now := time.Now()
	clock := func() time.Time { return now }
	prepared, e := prepareOfflineBackupWithPlan(ctx, cfg, body, keys, work, &backupPartialPreparation{trust: trust, plan: opts.PartialPlan, keysPlan: opts.PartialKeysPlan, completePlan: opts.KeysPlan, pairPlan: pair}, clock, func(string) error { return nil })
	if e != nil || !prepared.Complete || prepared.PairPlan.RelatedPlanCount == nil || *prepared.PairPlan.RelatedPlanCount != 3 {
		t.Fatal(prepared, e)
	}
	paths := []string{opts.PartialPlan, opts.PartialKeysPlan, opts.KeysPlan}
	// 別用途/領域内/別rootの署名済み計画を登録せず、出力計画も作らない。
	for i, related := range []BackupPairRelatedPlans{
		{PartialPlan: pair}, {PartialPlan: trust}, {KeysPlan: opts.PartialKeysPlan}, {PartialKeysPlan: opts.PartialPlan},
	} {
		rejectedPlan := filepath.Join(parent, fmt.Sprintf("rejected-%d.json", i))
		r, e := PlanBackupPairReclamationWithPlans(ctx, cfg, body, keys, trust, rejectedPlan, related)
		if e == nil || r.Planned {
			t.Fatal(r, e)
		}
		if _, e = os.Stat(rejectedPlan); !os.IsNotExist(e) {
			t.Fatal("invalid registration saved plan", e)
		}
	}
	collisionBase := filepath.Join(parent, "collision")
	rejected, e := PrepareOfflineBackupPlanned(ctx, cfg, collisionBase+"-body", collisionBase+"-keys", work, BackupPreparationPlans{TrustInstance: trust, PartialPlan: collisionBase + "-partial", PartialKeysPlan: collisionBase + "-partial" + backupKeysRetireSuffix, PairPlan: collisionBase + "-pair"})
	if e == nil || rejected.Capture != nil || rejected.Phase != "preflight" {
		t.Fatal("retirement pending collision accepted", rejected, e)
	}
	if _, e = os.Stat(collisionBase + "-body"); !os.IsNotExist(e) {
		t.Fatal("collision preflight created body", e)
	}
	otherKeys, otherPlan := filepath.Join(parent, "other-keys"), filepath.Join(parent, "other-partial-keys.json")
	if _, e := ExportPlannedBackupKeys(ctx, cfg, body, otherKeys, trust, otherPlan); e != nil {
		t.Fatal(e)
	}
	if _, e := PlanBackupPairReclamationWithPlans(ctx, cfg, body, keys, trust, filepath.Join(parent, "wrong-root.json"), BackupPairRelatedPlans{PartialKeysPlan: otherPlan}); e == nil {
		t.Fatal("other root registered")
	}
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-offline"); e != nil {
		t.Fatal(e)
	}
	r, e := reclaimBackupPair(ctx, body, keys, trust, pair, true, clock, func(string) error { return nil })
	if e != nil || r.Applied || r.RelatedRetiredCount == nil || *r.RelatedRetiredCount != 0 {
		t.Fatal(r, e)
	}
	pairRaw, e := os.ReadFile(pair)
	if e != nil {
		t.Fatal(e)
	}
	var pairEnv backupPairEnvelope
	if e = json.Unmarshal(pairRaw, &pairEnv); e != nil {
		t.Fatal(e)
	}
	var payload backupPairPlanV2
	if e = json.Unmarshal(pairEnv.Plan, &payload); e != nil {
		t.Fatal(e)
	}
	if payload.Schema != 3 || len(payload.Related) != 3 {
		t.Fatal(payload)
	}
	payload.Related = payload.Related[:2]
	pairEnv.Plan, e = json.Marshal(payload)
	if e != nil {
		t.Fatal(e)
	}
	pairEnv.SHA = sha256.Sum256(pairEnv.Plan)
	forged, e := json.Marshal(pairEnv)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(pair, forged, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = reclaimBackupPair(ctx, body, keys, trust, pair, true, clock, func(string) error { return nil }); e == nil {
		t.Fatal("unsigned related plan omission accepted")
	}
	if e = os.WriteFile(pair, pairRaw, 0600); e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(opts.KeysPlan)
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(25 * time.Hour)
	if e = os.WriteFile(opts.KeysPlan, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e = reclaimBackupPair(ctx, body, keys, trust, pair, true, clock, func(string) error { return nil })
	if e == nil || r.Applied {
		t.Fatal(r, e)
	}
	for _, path := range paths[:2] {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var env backupKeysPlanEnvelope
		if e = json.Unmarshal(raw, &env); e != nil || env.Retired {
			t.Fatal("plan mutated before all authentication", env, e)
		}
	}
	if e = os.WriteFile(opts.KeysPlan, original, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(opts.KeysPlan, opts.KeysPlan+"-missing"); e != nil {
		t.Fatal(e)
	}
	if _, e = reclaimBackupPair(ctx, body, keys, trust, pair, true, clock, func(string) error { return nil }); e == nil {
		t.Fatal("missing related plan ignored")
	}
	if e = os.Rename(opts.KeysPlan+"-missing", opts.KeysPlan); e != nil {
		t.Fatal(e)
	}
	stop := errors.New("stop after first retirement")
	r, e = reclaimBackupPair(ctx, body, keys, trust, pair, true, clock, func(stage string) error {
		if stage == "pair:related_plan_retired" {
			return stop
		}
		return nil
	})
	if !errors.Is(e, stop) || r.Applied || *r.RelatedRetiredCount != 1 {
		t.Fatal(r, e)
	}
	if _, e = os.Stat(filepath.Join(body, "manifest.json")); e != nil {
		t.Fatal("body deleted before all plans retired", e)
	}
	if _, e = os.Stat(filepath.Join(keys, "keys/master-000001.key")); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(opts.PartialKeysPlan+backupKeysRetireSuffix, []byte("occupied"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = reclaimBackupPair(ctx, body, keys, trust, pair, true, clock, func(string) error { return nil }); e == nil {
		t.Fatal("pending overwritten")
	}
	if _, e = os.Stat(filepath.Join(body, "manifest.json")); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(opts.PartialKeysPlan + backupKeysRetireSuffix); e != nil {
		t.Fatal(e)
	}
	r, e = reclaimBackupPair(ctx, body, keys, trust, pair, true, clock, func(stage string) error {
		if stage == "pair:body_removed" {
			for _, path := range paths {
				raw, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				var env backupKeysPlanEnvelope
				if e = json.Unmarshal(raw, &env); e != nil || !env.Retired {
					t.Fatal("root removed before retirement", env, e)
				}
			}
			return stop
		}
		return nil
	})
	if !errors.Is(e, stop) || !r.BodyRemoved || *r.RelatedRetiredCount != 3 || r.Applied {
		t.Fatal(r, e)
	}
	// 外部で使用済み印が巻き戻された状態も、鍵の回収前に再認証して退役する。
	var rolled backupKeysPlanEnvelope
	retiredRaw, e := os.ReadFile(opts.KeysPlan)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(retiredRaw, &rolled); e != nil {
		t.Fatal(e)
	}
	rolled.Retired = false
	rolledRaw, e := json.Marshal(rolled)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(opts.KeysPlan, rolledRaw, 0600); e != nil {
		t.Fatal(e)
	}
	files := 0
	r, e = reclaimBackupPair(ctx, body, keys, trust, pair, true, clock, func(stage string) error {
		if stage == "keys:backup:reclaim_file" {
			files++
			if files == 2 {
				return stop
			}
		}
		return nil
	})
	if !errors.Is(e, stop) || !r.BodyRemoved || r.Applied || *r.RelatedRetiredCount != 3 {
		t.Fatal(r, e)
	}
	if _, e = os.Stat(filepath.Join(keys, "keys/evidence-000010.seed")); !os.IsNotExist(e) {
		t.Fatal("seed not removed at injected boundary", e)
	}
	r, e = reclaimBackupPair(ctx, body, keys, trust, pair, true, clock, func(string) error { return nil })
	if e != nil || !r.Applied || !r.KeysRemoved || *r.RelatedRetiredCount != 3 {
		t.Fatal(r, e)
	}
	if e = os.Mkdir(body, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(ctx, body, trust, opts.PartialPlan, true); e == nil {
		t.Fatal("retired body plan reused")
	}
	if e = os.Mkdir(keys, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackupKeys(ctx, keys, trust, opts.PartialKeysPlan, true); e == nil {
		t.Fatal("retired partial keys plan reused")
	}
	if _, e = ReclaimBackupKeysPlanned(ctx, keys, trust, opts.KeysPlan, true); e == nil {
		t.Fatal("retired complete keys plan reused")
	}
}
