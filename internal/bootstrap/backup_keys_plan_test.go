// 公開信頼根と署名計画の束縛、正本喪失後の期限回収、鍵/完成印削除後の再開を検証する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPlannedBackupKeysReclaimWithoutSource(t *testing.T) {
	cfg, backup := backupFixture(t)
	past := time.Now().Add(-25 * time.Hour)
	clock := func() time.Time { return past }
	if _, e := captureOfflineBackup(context.Background(), cfg, backup, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	keys := filepath.Join(filepath.Dir(backup), "keys")
	if _, e := exportBackupKeys(context.Background(), cfg, backup, keys, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	controls := expiredSweepParent(t)
	trust, plan := filepath.Join(controls, "trust.json"), filepath.Join(controls, "plan.json")
	exported, e := ExportBackupTrust(context.Background(), cfg, trust)
	if e != nil || !exported.Exported || exported.RestoreReady || exported.SigningKeyID != 10 {
		t.Fatal(exported, e)
	}
	planned, e := planBackupKeysReclamation(context.Background(), cfg, keys, trust, plan, clock)
	if e != nil || !planned.Planned || planned.Backup.Expired || planned.RestoreReady {
		t.Fatal(planned, e)
	}
	if _, e = PlanBackupKeysReclamation(context.Background(), cfg, keys, trust, plan); e == nil {
		t.Fatal("plan overwritten")
	}
	if _, e = ExportBackupTrust(context.Background(), cfg, trust); e == nil {
		t.Fatal("trust overwritten")
	}
	if _, e = PlanBackupKeysReclamation(context.Background(), cfg, keys, trust, filepath.Join(keys, "plan.json")); e == nil {
		t.Fatal("plan inside keys")
	}
	finalKeys, finalPlan := keys+"-final", plan+"-final"
	if _, e = exportBackupKeys(context.Background(), cfg, backup, finalKeys, clock, func(string) {}); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(finalKeys, "keys/master-000001.key")); e != nil {
		t.Fatal(e)
	}
	partialPlan, e := PlanBackupKeysReclamation(context.Background(), cfg, finalKeys, trust, finalPlan)
	if e != nil || !partialPlan.Planned || !partialPlan.Backup.Expired {
		t.Fatal(partialPlan, e)
	}
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	before := func() time.Time { return past.Add(time.Minute) }
	retained, e := reclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true, before, func(string) error { return nil })
	if e != nil || retained.Expired || retained.Applied || retained.Verified {
		t.Fatal(retained, e)
	}
	if _, e = verifyBackupWithKeys(context.Background(), backup, keys, before); e != nil {
		t.Fatal("unexpired artifacts changed", e)
	}
	if _, e = reclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true, func() time.Time { return past.Add(-time.Minute) }, func(string) error { return nil }); e == nil {
		t.Fatal("clock regression accepted")
	}
	original, e := os.ReadFile(plan)
	if e != nil {
		t.Fatal(e)
	}
	copyPlan := plan + "-copy"
	if e = os.WriteFile(copyPlan, original, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), keys, trust, copyPlan, true); e == nil {
		t.Fatal("plan path alias accepted")
	}
	trustRaw, e := os.ReadFile(trust)
	if e != nil {
		t.Fatal(e)
	}
	var wrong instance
	if e = json.Unmarshal(trustRaw, &wrong); e != nil {
		t.Fatal(e)
	}
	wrong.SigningPublic[0] ^= 1
	wrongRaw, _ := json.Marshal(wrong)
	if e = os.WriteFile(trust, wrongRaw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true); e == nil {
		t.Fatal("wrong trust accepted")
	}
	if e = os.WriteFile(trust, trustRaw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(plan, plan+"-hardlink"); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true); e == nil {
		t.Fatal("hardlinked plan accepted")
	}
	if e = os.Remove(plan + "-hardlink"); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(keys, keys+"-moved"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(keys, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true); e == nil {
		t.Fatal("live root replaced")
	}
	if e = os.Remove(keys); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(keys+"-moved", keys); e != nil {
		t.Fatal(e)
	}
	var env backupKeysPlanEnvelope
	if e = json.Unmarshal(original, &env); e != nil {
		t.Fatal(e)
	}
	var p backupKeysCleanupPlan
	if e = json.Unmarshal(env.Plan, &p); e != nil {
		t.Fatal(e)
	}
	p.Root = "/"
	env.Plan, _ = json.Marshal(p)
	env.SHA = sha256.Sum256(env.Plan)
	tampered, _ := json.Marshal(env)
	if e = os.WriteFile(plan, tampered, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true); e == nil {
		t.Fatal("rehash forgery accepted")
	}
	if e = os.WriteFile(plan, original, 0600); e != nil {
		t.Fatal(e)
	}
	unknown := filepath.Join(keys, "unknown")
	if e = os.WriteFile(unknown, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true); e == nil {
		t.Fatal("unknown file accepted")
	}
	if e = os.Remove(unknown); e != nil {
		t.Fatal(e)
	}
	bundle := filepath.Join(keys, "bundle.json")
	bundleRaw, e := os.ReadFile(bundle)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(bundle, append(append([]byte{}, bundleRaw...), '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true); e == nil {
		t.Fatal("bundle bytes changed")
	}
	if e = os.WriteFile(bundle, bundleRaw, 0600); e != nil {
		t.Fatal(e)
	}
	preview, e := ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, false)
	if e != nil || !preview.Expired || preview.Applied || preview.RestoreReady {
		t.Fatal(preview, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = ReclaimBackupKeysPlanned(ctx, keys, trust, plan, true); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	stop := errors.New("interrupted")
	if _, e = reclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true, time.Now, func(string) error {
		if _, e := os.Stat(filepath.Join(keys, "keys/master-000001.key")); errors.Is(e, os.ErrNotExist) {
			return stop
		}
		return nil
	}); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if _, e = os.Stat(bundle); e != nil {
		t.Fatal("completion mark lost", e)
	}
	// 計画と信頼根だけで署名seed/master欠落後も認証し、manifest除去直後に再び止める。
	if _, e = reclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true, time.Now, func(stage string) error {
		if stage == "backup:reclaim_manifest" {
			return stop
		}
		return nil
	}); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if _, e = os.Stat(bundle); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("manifest remains", e)
	}
	done, e := ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true)
	if e != nil || !done.Applied || !done.Expired || done.Verified || done.RestoreReady {
		t.Fatal(done, e)
	}
	if _, e = os.Stat(keys); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("root remains", e)
	}
	for _, path := range []string{trust, plan, filepath.Join(backup, "manifest.json")} {
		if _, e = os.Stat(path); e != nil {
			t.Fatal("independent artifact changed", e)
		}
	}
	// 使用済み印を同期した後は、inode再利用の有無にかかわらず古い計画を適用しない。
	if e = os.Mkdir(keys, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), keys, trust, plan, true); e == nil {
		t.Fatal("root replacement accepted")
	}
	if _, e = reclaimBackupKeysPlanned(context.Background(), finalKeys, trust, finalPlan, true, time.Now, func(stage string) error {
		if stage == "backup:keys_plan_retired" {
			return stop
		}
		return nil
	}); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(finalKeys)
	if e != nil || len(entries) != 0 {
		t.Fatal("retired root not empty", entries, e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), finalKeys, trust, finalPlan, true); e == nil {
		t.Fatal("retired plan reused")
	}
}
