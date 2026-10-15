// 事前署名計画を持つ未完成コピーの境界・改変拒否・期限回収・中断再開を検証する。
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

	"oimobbs/internal/platform"
)

func TestPlannedPartialBackupLifecycle(t *testing.T) {
	cfg, output := backupFixture(t)
	parent, controls := filepath.Dir(output), expiredSweepParent(t)
	trust := filepath.Join(controls, "trust.json")
	if _, e := ExportBackupTrust(context.Background(), cfg, trust); e != nil {
		t.Fatal(e)
	}
	paths := func(name string) (string, string) {
		return filepath.Join(parent, name), filepath.Join(controls, name+".json")
	}
	// 正本排他中の失敗は計画/コピーを作らず、未取得IDも結果へ含めない。
	lock, e := platform.Lock(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	busyRoot, busyPlan := paths("busy")
	busy, e := CapturePlannedOfflineBackup(context.Background(), cfg, busyRoot, trust, busyPlan)
	if e == nil || busy.Planned || busy.Capture != nil {
		t.Fatal(busy, e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	past := time.Now().Add(-25 * time.Hour)
	clock := func() time.Time { return past }
	stages := map[string]string{"empty": "backup:partial_plan_synced", "file": "backup:file", "pending": "backup:manifest_synced", "retire": "backup:file"}
	for _, name := range []string{"empty", "file", "pending", "retire"} {
		root, plan := paths(name)
		ctx, cancel := context.WithCancel(context.Background())
		report, e := capturePlannedOfflineBackup(ctx, cfg, root, trust, plan, clock, func(stage string) {
			if stage == stages[name] {
				cancel()
			}
		})
		cancel()
		if !errors.Is(e, context.Canceled) || !report.Planned || report.Complete || report.Capture == nil || report.Capture.Verified {
			t.Fatal(name, report, e)
		}
		if _, e = os.Stat(filepath.Join(root, "manifest.json")); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("completion installed", name, e)
		}
	}
	completeRoot, completePlan := paths("complete")
	complete, e := capturePlannedOfflineBackup(context.Background(), cfg, completeRoot, trust, completePlan, clock, func(string) {})
	if e != nil || !complete.Planned || !complete.Complete || !complete.Capture.Verified || complete.RestoreReady {
		t.Fatal(complete, e)
	}
	freshRoot, freshPlan := paths("fresh")
	freshCtx, cancelFresh := context.WithCancel(context.Background())
	fresh, e := capturePlannedOfflineBackup(freshCtx, cfg, freshRoot, trust, freshPlan, time.Now, func(stage string) {
		if stage == "backup:file" {
			cancelFresh()
		}
	})
	cancelFresh()
	if !errors.Is(e, context.Canceled) || !fresh.Planned {
		t.Fatal(fresh, e)
	}
	// 既存計画/不正配置はpayload/rootの作成前に拒否する。
	duplicateRoot, _ := paths("duplicate")
	duplicate, e := CapturePlannedOfflineBackup(context.Background(), cfg, duplicateRoot, trust, freshPlan)
	if e == nil || duplicate.Phase != "preflight" {
		t.Fatal(duplicate, e)
	}
	if _, e = os.Stat(duplicateRoot); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("preflight wrote root", e)
	}
	if _, e = CapturePlannedOfflineBackup(context.Background(), cfg, duplicateRoot, trust, filepath.Join(duplicateRoot, "plan.json")); e == nil {
		t.Fatal("plan in root accepted")
	}
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	emptyRoot, emptyPlan := paths("empty")
	before, e := reclaimPartialBackup(context.Background(), emptyRoot, trust, emptyPlan, true, func() time.Time { return past.Add(time.Minute) }, func(string) error { return nil })
	if e != nil || before.Expired || before.Applied || before.Verified {
		t.Fatal(before, e)
	}
	if _, e = reclaimPartialBackup(context.Background(), emptyRoot, trust, emptyPlan, true, func() time.Time { return past.Add(-time.Minute) }, func(string) error { return nil }); e == nil {
		t.Fatal("clock regression accepted")
	}
	for _, apply := range []bool{false, true} {
		if _, e = ReclaimPartialBackup(context.Background(), completeRoot, trust, completePlan, apply); e == nil {
			t.Fatal("completed backup accepted")
		}
	}
	if _, e = os.Stat(filepath.Join(completeRoot, "manifest.json")); e != nil {
		t.Fatal("complete changed", e)
	}
	retained, e := ReclaimPartialBackup(context.Background(), freshRoot, trust, freshPlan, true)
	if e != nil || retained.Expired || retained.Applied || retained.Verified {
		t.Fatal(retained, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = ReclaimPartialBackup(ctx, emptyRoot, trust, emptyPlan, true); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	trustOriginal, e := os.ReadFile(trust)
	if e != nil {
		t.Fatal(e)
	}
	var wrongTrust instance
	if e = json.Unmarshal(trustOriginal, &wrongTrust); e != nil {
		t.Fatal(e)
	}
	wrongTrust.SigningPublic[0] ^= 1
	wrongRaw, _ := json.Marshal(wrongTrust)
	if e = os.WriteFile(trust, wrongRaw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), emptyRoot, trust, emptyPlan, true); e == nil {
		t.Fatal("wrong trust accepted")
	}
	if e = os.WriteFile(trust, trustOriginal, 0600); e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(emptyPlan)
	if e != nil {
		t.Fatal(e)
	}
	var env backupKeysPlanEnvelope
	if e = json.Unmarshal(original, &env); e != nil {
		t.Fatal(e)
	}
	var p backupPartialCleanupPlan
	if e = json.Unmarshal(env.Plan, &p); e != nil {
		t.Fatal(e)
	}
	p.Root = "/"
	env.Plan, _ = json.Marshal(p)
	env.SHA = sha256.Sum256(env.Plan)
	forged, _ := json.Marshal(env)
	if e = os.WriteFile(emptyPlan, forged, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), emptyRoot, trust, emptyPlan, true); e == nil {
		t.Fatal("rehash forgery accepted")
	}
	if e = os.WriteFile(emptyPlan, original, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), emptyRoot, trust, emptyPlan, true); e == nil {
		t.Fatal("partial signature accepted for keys")
	}
	alias := emptyPlan + "-alias"
	if e = os.WriteFile(alias, original, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), emptyRoot, trust, alias, true); e == nil {
		t.Fatal("plan alias accepted")
	}
	if e = os.Link(emptyPlan, emptyPlan+"-link"); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), emptyRoot, trust, emptyPlan, true); e == nil {
		t.Fatal("hardlinked plan accepted")
	}
	if e = os.Remove(emptyPlan + "-link"); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(emptyRoot, emptyRoot+"-moved"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(emptyRoot, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), emptyRoot, trust, emptyPlan, true); e == nil {
		t.Fatal("root replacement accepted")
	}
	if e = os.Remove(emptyRoot); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(emptyRoot+"-moved", emptyRoot); e != nil {
		t.Fatal(e)
	}
	unknown := filepath.Join(emptyRoot, "unknown")
	if e = os.WriteFile(unknown, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), emptyRoot, trust, emptyPlan, true); e == nil {
		t.Fatal("unknown payload accepted")
	}
	if e = os.Remove(unknown); e != nil {
		t.Fatal(e)
	}
	fileRoot, filePlan := paths("file")
	raw, e := os.ReadFile(filePlan)
	if e != nil {
		t.Fatal(e)
	}
	marker, trustRaw, e := loadBackupTrust(trust)
	if e != nil {
		t.Fatal(e)
	}
	fileP, e := decodeBackupPartialPlan(raw, marker, trustRaw)
	if e != nil {
		t.Fatal(e)
	}
	var actual string
	var length int64
	for _, entry := range fileP.Manifest.Entries {
		for _, f := range entry.Files {
			path := filepath.Join(fileRoot, filepath.FromSlash(backupEntryPath(entry)+"/"+f.Name))
			if _, e := os.Stat(path); e == nil {
				actual = path
				length = int64(f.Length)
			}
		}
	}
	if actual == "" || length < 2 {
		t.Fatal("no copied payload")
	}
	if e = os.Truncate(actual, length+1); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), fileRoot, trust, filePlan, true); e == nil {
		t.Fatal("oversize payload accepted")
	}
	if e = os.Truncate(actual, length/2); e != nil {
		t.Fatal(e)
	}
	preview, e := ReclaimPartialBackup(context.Background(), fileRoot, trust, filePlan, false)
	if e != nil || !preview.Expired || preview.Applied || preview.Verified {
		t.Fatal(preview, e)
	}
	pendingRoot, pendingPlan := paths("pending")
	pendingFile := filepath.Join(pendingRoot, "manifest.pending")
	pendingRaw, e := os.ReadFile(pendingFile)
	if e != nil {
		t.Fatal(e)
	}
	changed := append([]byte{}, pendingRaw...)
	changed[0] ^= 1
	if e = os.WriteFile(pendingFile, changed, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), pendingRoot, trust, pendingPlan, true); e == nil {
		t.Fatal("full pending changed")
	}
	if e = os.WriteFile(pendingFile, pendingRaw[:len(pendingRaw)/2], 0600); e != nil {
		t.Fatal(e)
	}
	stop := errors.New("cleanup boundary stop")
	if _, e = reclaimPartialBackup(context.Background(), fileRoot, trust, filePlan, true, time.Now, func(stage string) error {
		if stage == "backup:reclaim_file" {
			return stop
		}
		return nil
	}); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if _, e = reclaimPartialBackup(context.Background(), pendingRoot, trust, pendingPlan, true, time.Now, func(stage string) error {
		if stage == "backup:reclaim_manifest" {
			return stop
		}
		return nil
	}); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	retiredPending := emptyPlan + backupKeysRetireSuffix
	if e = os.WriteFile(retiredPending, []byte("unfinished retirement"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), emptyRoot, trust, emptyPlan, true); e == nil {
		t.Fatal("retirement pending overwritten")
	}
	if _, e = os.Stat(emptyRoot); e != nil {
		t.Fatal("root removed despite pending", e)
	}
	if e = os.Remove(retiredPending); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"empty", "file", "pending"} {
		root, plan := paths(name)
		reclaimed, e := ReclaimPartialBackup(context.Background(), root, trust, plan, true)
		if e != nil || !reclaimed.Applied || !reclaimed.Expired || reclaimed.Verified || reclaimed.RestoreReady {
			t.Fatal(name, reclaimed, e)
		}
		if _, e = os.Stat(root); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("root remains", name, e)
		}
		if e = os.Mkdir(root, 0700); e != nil {
			t.Fatal(e)
		}
		if _, e = ReclaimPartialBackup(context.Background(), root, trust, plan, true); e == nil {
			t.Fatal("retired plan reused", name)
		}
	}
	retireRoot, retirePlan := paths("retire")
	if _, e = reclaimPartialBackup(context.Background(), retireRoot, trust, retirePlan, true, time.Now, func(stage string) error {
		if stage == "backup:partial_plan_retired" {
			return stop
		}
		return nil
	}); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if _, e = ReclaimPartialBackup(context.Background(), retireRoot, trust, retirePlan, true); e == nil {
		t.Fatal("retired residual reclaimed")
	}
	if entries, e := os.ReadDir(retireRoot); e != nil || len(entries) != 0 {
		t.Fatal(entries, e)
	}
	if _, e = os.Stat(trust); e != nil {
		t.Fatal(e)
	}
}
