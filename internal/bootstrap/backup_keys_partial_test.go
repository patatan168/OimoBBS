// 未完成鍵束の事前計画・改変拒否・正本喪失後回収・中断再開と一括作成を検証する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/platform"
)

func TestPartialBackupKeysLifecycle(t *testing.T) {
	cfg, body := backupFixture(t)
	parent := filepath.Dir(body)
	trust := filepath.Join(parent, "trust.json")
	if _, e := ExportBackupTrust(context.Background(), cfg, trust); e != nil {
		t.Fatal(e)
	}
	if _, e := CaptureOfflineBackup(context.Background(), cfg, body); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	clock := func() time.Time { return now }
	paths := func(name string) (string, string) {
		return filepath.Join(parent, name), filepath.Join(parent, name+"-plan.json")
	}

	lock, e := platform.Lock(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	busyRoot, busyPlan := paths("busy")
	busy, e := ExportPlannedBackupKeys(context.Background(), cfg, body, busyRoot, trust, busyPlan)
	if e == nil || busy.Phase != "source_open" || busy.Planned || busy.Keys != nil {
		t.Fatal(busy, e)
	}
	if _, e = json.Marshal(busy); e != nil {
		t.Fatal(e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	for _, plans := range [][2]string{{filepath.Join(body, "keys-out"), filepath.Join(parent, "bad-plan")}, {filepath.Join(parent, "bad-out"), filepath.Join(body, "plan")}, {filepath.Join(parent, "bad-out"), trust}} {
		rejected, err := ExportPlannedBackupKeys(context.Background(), cfg, body, plans[0], trust, plans[1])
		if err == nil || rejected.Phase != "preflight" || rejected.Planned {
			t.Fatal(rejected, err)
		}
	}
	unplannedRoot, unplannedPlan := paths("unplanned")
	unplannedCtx, cancelUnplanned := context.WithCancel(context.Background())
	unplanned, err := exportPlannedBackupKeys(unplannedCtx, cfg, body, unplannedRoot, trust, unplannedPlan, clock, func(stage string) {
		if stage == "backup-keys:directory" {
			cancelUnplanned()
		}
	})
	cancelUnplanned()
	if !errors.Is(err, context.Canceled) || unplanned.Planned || unplanned.Complete {
		t.Fatal(unplanned, err)
	}
	if _, err = ReclaimPartialBackupKeys(context.Background(), unplannedRoot, trust, unplannedPlan, true); err == nil {
		t.Fatal("root without plan reclaimed")
	}
	if entries, err := os.ReadDir(unplannedRoot); err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
	for _, name := range []string{"empty", "file", "pending", "retire"} {
		root, plan := paths(name)
		ctx, cancel := context.WithCancel(context.Background())
		files := 0
		report, err := exportPlannedBackupKeys(ctx, cfg, body, root, trust, plan, clock, func(stage string) {
			if stage == "backup-keys:partial_plan_synced" {
				entries, readErr := os.ReadDir(root)
				if readErr != nil || len(entries) != 0 {
					t.Fatal("keys preceded plan", entries, readErr)
				}
				if name == "empty" {
					cancel()
				}
			}
			if stage == "backup-keys:file" {
				files++
				if (name == "file" || name == "retire") && files == 2 {
					cancel()
				}
			}
			if stage == "backup-keys:manifest_synced" && name == "pending" {
				cancel()
			}
		})
		cancel()
		if !errors.Is(err, context.Canceled) || !report.Planned || report.Complete || report.Keys == nil || report.Keys.Verified || report.RestoreReady {
			t.Fatal(name, report, err)
		}
		if _, err = os.Stat(filepath.Join(root, "bundle.json")); !os.IsNotExist(err) {
			t.Fatal("completion installed", name, err)
		}
	}
	completeRoot, completePlan := paths("complete")
	complete, e := ExportPlannedBackupKeys(context.Background(), cfg, body, completeRoot, trust, completePlan)
	if e != nil || !complete.Complete || !complete.Planned || !complete.Keys.Verified {
		t.Fatal(complete, e)
	}
	if _, e = VerifyBackupWithKeys(context.Background(), body, completeRoot); e != nil {
		t.Fatal(e)
	}
	duplicate, e := ExportPlannedBackupKeys(context.Background(), cfg, body, completeRoot, trust, completePlan)
	if e == nil || duplicate.Phase != "preflight" || duplicate.Planned {
		t.Fatal(duplicate, e)
	}

	// 両計画の一括作成。鍵計画も最初の鍵file前に保存され、同じ正本排他を維持する。
	work := filepath.Join(parent, "work")
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	preparedBody, bodyPlan := paths("prepared")
	preparedKeys, keyPlan := paths("prepared-keys")
	stages := []string{}
	prepared, e := prepareOfflineBackupWithPlan(context.Background(), cfg, preparedBody, preparedKeys, work, &backupPartialPreparation{trust: trust, plan: bodyPlan, keysPlan: keyPlan}, time.Now, func(stage string) error {
		stages = append(stages, stage)
		if stage == "source_closed" {
			return nil
		}
		if locked, err := platform.Lock(cfg.DataDir); err == nil {
			_ = platform.Unlock(locked)
			t.Fatal("source lock lost")
		}
		if stage == "keys_partial_plan_synced" {
			entries, err := os.ReadDir(preparedKeys)
			if err != nil || len(entries) != 0 {
				t.Fatal("keys preceded preparation plan", entries, err)
			}
		}
		return nil
	})
	if e != nil || !prepared.Complete || !*prepared.PartialPlanned || prepared.KeysPartialPlanned == nil || !*prepared.KeysPartialPlanned || !prepared.Replay.Replayed {
		t.Fatal(prepared, e)
	}
	if !reflect.DeepEqual(stages, []string{"partial_plan_synced", "capture_complete", "keys_partial_plan_synced", "keys_complete", "source_closed"}) {
		t.Fatal(stages)
	}
	for _, invalid := range []string{bodyPlan, filepath.Join(work, "bad-plan"), filepath.Join(parent, "reject-keys", "plan"), completePlan} {
		rejected, err := PrepareOfflineBackupWithPlans(context.Background(), cfg, filepath.Join(parent, "reject-body"), filepath.Join(parent, "reject-keys"), work, trust, filepath.Join(parent, "reject-body-plan"), invalid)
		if err == nil || rejected.Phase != "preflight" || *rejected.PartialPlanned || *rejected.KeysPartialPlanned {
			t.Fatal(rejected, err)
		}
		if _, err = os.Stat(filepath.Join(parent, "reject-body")); !os.IsNotExist(err) {
			t.Fatal("preflight created body", err)
		}
	}
	stoppedBody, stoppedBodyPlan := paths("stopped-body")
	stoppedKeys, stoppedKeysPlan := paths("stopped-keys")
	stop := errors.New("stop at keys plan")
	stopped, e := prepareOfflineBackupWithPlan(context.Background(), cfg, stoppedBody, stoppedKeys, work, &backupPartialPreparation{trust: trust, plan: stoppedBodyPlan, keysPlan: stoppedKeysPlan}, time.Now, func(stage string) error {
		if stage == "keys_partial_plan_synced" {
			return stop
		}
		return nil
	})
	if !errors.Is(e, stop) || stopped.Complete || stopped.Phase != "keys" || !stopped.Capture.Verified || !*stopped.KeysPartialPlanned || stopped.Keys == nil || stopped.Keys.Verified {
		t.Fatal(stopped, e)
	}
	if _, e = json.Marshal(stopped); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	expiredClock := func() time.Time { return now.Add(25 * time.Hour) }
	if _, e = reclaimPartialBackupKeys(context.Background(), completeRoot, trust, completePlan, true, expiredClock, func(string) error { return nil }); e == nil {
		t.Fatal("completed keys reclaimed")
	}

	// 削除対象集合/長さ/署名の改変を保持して拒否する。
	pendingRoot, pendingPlan := paths("pending")
	pendingPath := filepath.Join(pendingRoot, "bundle.pending")
	pendingRaw, e := os.ReadFile(pendingPath)
	if e != nil {
		t.Fatal(e)
	}
	planRaw, e := os.ReadFile(pendingPlan)
	if e != nil {
		t.Fatal(e)
	}
	assertRejected := func() {
		t.Helper()
		r, err := reclaimPartialBackupKeys(context.Background(), pendingRoot, trust, pendingPlan, true, expiredClock, func(string) error { return nil })
		if err == nil || r.Applied {
			t.Fatal("unsafe partial keys accepted", r, err)
		}
		if _, err = os.Stat(pendingRoot); err != nil {
			t.Fatal("rejected root removed", err)
		}
	}
	write := func(path string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	extra := filepath.Join(pendingRoot, "unknown")
	write(extra, []byte("unknown"))
	assertRejected()
	if e = os.Remove(extra); e != nil {
		t.Fatal(e)
	}
	completed := filepath.Join(pendingRoot, "bundle.json")
	write(completed, pendingRaw)
	assertRejected()
	if e = os.Remove(completed); e != nil {
		t.Fatal(e)
	}
	write(pendingPath, append(append([]byte{}, pendingRaw...), 0))
	assertRejected()
	altered := append([]byte{}, pendingRaw...)
	altered[0] ^= 1
	write(pendingPath, altered)
	assertRejected()
	write(pendingPath, pendingRaw)
	master := filepath.Join(pendingRoot, "keys/master-000001.key")
	masterRaw, e := os.ReadFile(master)
	if e != nil {
		t.Fatal(e)
	}
	write(master, append(append([]byte{}, masterRaw...), 0))
	assertRejected()
	write(master, masterRaw)
	alias := filepath.Join(parent, "hardlink")
	if e = os.Link(master, alias); e != nil {
		t.Fatal(e)
	}
	assertRejected()
	if e = os.Remove(alias); e != nil {
		t.Fatal(e)
	}
	masterSaved := master + "-saved"
	if e = os.Rename(master, masterSaved); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(masterSaved, master); e != nil {
		t.Fatal(e)
	}
	assertRejected()
	if e = os.Remove(master); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(masterSaved, master); e != nil {
		t.Fatal(e)
	}
	planAlias := filepath.Join(parent, "alias-plan.json")
	write(planAlias, planRaw)
	if _, e = reclaimPartialBackupKeys(context.Background(), pendingRoot, trust, planAlias, true, expiredClock, func(string) error { return nil }); e == nil {
		t.Fatal("plan alias accepted")
	}
	if _, e = reclaimPartialBackupKeys(context.Background(), pendingRoot, trust, pendingPlan, true, func() time.Time { return now.Add(-time.Second) }, func(string) error { return nil }); e == nil {
		t.Fatal("clock regression accepted")
	}
	canceledCtx, cancelReclaim := context.WithCancel(context.Background())
	cancelReclaim()
	if _, e = ReclaimPartialBackupKeys(canceledCtx, pendingRoot, trust, pendingPlan, true); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	var env backupKeysPlanEnvelope
	if e = json.Unmarshal(planRaw, &env); e != nil {
		t.Fatal(e)
	}
	var plan backupPartialKeysPlan
	if e = json.Unmarshal(env.Plan, &plan); e != nil {
		t.Fatal(e)
	}
	plan.Root = "/"
	env.Plan, e = json.Marshal(plan)
	if e != nil {
		t.Fatal(e)
	}
	env.SHA = sha256.Sum256(env.Plan)
	forged, e := json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	write(pendingPlan, forged)
	assertRejected()
	write(pendingPlan, planRaw)
	trustRaw, e := os.ReadFile(trust)
	if e != nil {
		t.Fatal(e)
	}
	write(trust, append(append([]byte{}, trustRaw...), '\n'))
	assertRejected()
	write(trust, trustRaw)
	renamed := pendingRoot + "-old"
	if e = os.Rename(pendingRoot, renamed); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(pendingRoot, 0700); e != nil {
		t.Fatal(e)
	}
	assertRejected()
	if e = os.Remove(pendingRoot); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(renamed, pendingRoot); e != nil {
		t.Fatal(e)
	}
	// 短いpayload/pendingと欠落は許容する。内容を有効な鍵束として認証はしない。
	write(master, masterRaw[:8])
	clear(masterRaw)
	write(pendingPath, pendingRaw[:7])
	if e = os.Remove(filepath.Join(pendingRoot, "keys/evidence-000010.seed")); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupKeysPlanned(context.Background(), pendingRoot, trust, pendingPlan, true); e == nil {
		t.Fatal("partial signature accepted as completed-key plan")
	}
	if _, e = ReclaimPartialBackup(context.Background(), pendingRoot, trust, pendingPlan, true); e == nil {
		t.Fatal("key signature accepted as body plan")
	}
	for _, name := range []string{"empty", "file", "pending", "stopped-keys"} {
		root, plan := paths(name)
		if name == "stopped-keys" {
			root, plan = stoppedKeys, stoppedKeysPlan
		}
		fresh, err := reclaimPartialBackupKeys(context.Background(), root, trust, plan, true, time.Now, func(string) error { return nil })
		if err != nil || fresh.Applied || fresh.Expired || fresh.Verified || fresh.Replayed || fresh.RestoreReady {
			t.Fatal(name, fresh, err)
		}
		preview, err := reclaimPartialBackupKeys(context.Background(), root, trust, plan, false, expiredClock, func(string) error { return nil })
		if err != nil || !preview.Expired || preview.Applied {
			t.Fatal(name, preview, err)
		}
		removedFiles := 0
		interrupted, err := reclaimPartialBackupKeys(context.Background(), root, trust, plan, true, expiredClock, func(stage string) error {
			if stage == "backup:reclaim_file" {
				removedFiles++
				if removedFiles == 3 {
					return stop
				}
			}
			return nil
		})
		if !errors.Is(err, stop) || interrupted.Applied {
			t.Fatal(name, interrupted, err)
		}
		done, err := reclaimPartialBackupKeys(context.Background(), root, trust, plan, true, expiredClock, func(string) error { return nil })
		if err != nil || !done.Applied || done.Verified || done.RestoreReady {
			t.Fatal(name, done, err)
		}
		if _, err = reclaimPartialBackupKeys(context.Background(), root, trust, plan, true, expiredClock, func(string) error { return nil }); err == nil {
			t.Fatal("retired plan reused")
		}
	}
	retireRoot, retirePlan := paths("retire")
	beforeRetire, e := reclaimPartialBackupKeys(context.Background(), retireRoot, trust, retirePlan, true, expiredClock, func(stage string) error {
		if stage == "backup:reclaim_manifest" {
			return stop
		}
		return nil
	})
	if !errors.Is(e, stop) || beforeRetire.Applied {
		t.Fatal(beforeRetire, e)
	}
	retired, e := reclaimPartialBackupKeys(context.Background(), retireRoot, trust, retirePlan, true, expiredClock, func(stage string) error {
		if stage == "backup:partial_keys_plan_retired" {
			return stop
		}
		return nil
	})
	if !errors.Is(e, stop) || retired.Applied {
		t.Fatal(retired, e)
	}
	if entries, err := os.ReadDir(retireRoot); err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
	if _, e = reclaimPartialBackupKeys(context.Background(), retireRoot, trust, retirePlan, true, expiredClock, func(string) error { return nil }); e == nil {
		t.Fatal("retired residual root accepted")
	}
	if _, e = os.Stat(filepath.Join(stoppedBody, "manifest.json")); e != nil {
		t.Fatal("completed body deleted", e)
	}
	if _, e = os.Stat(trust); e != nil {
		t.Fatal("trust deleted", e)
	}
}
