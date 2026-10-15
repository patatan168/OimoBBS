// バックアップCLIのコピー・照合・読取り回収と、入力拒否を確認する。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/bootstrap"
	"oimobbs/internal/platform"
)

func TestBackupCLI(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "data"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:8080", BaseURL: "http://127.0.0.1:8080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:8081", Origin: "http://127.0.0.1:8081", Transport: "loopback_tunnel"}, TrustedProxies: []string{}, CacheBytes: 268435456, EgressBits: 80000000}
	if _, e := bootstrap.Initialize(cfg, "backup CLI"); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	config := filepath.Join(parent, "config.json")
	if e = os.WriteFile(config, raw, 0600); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(parent, "copy")
	for _, step := range [][]string{{"capture", "--output", output}, {"verify", "--input", output}, {"reclaim", "--input", output, "--apply"}} {
		args := append([]string{"backup"}, step...)
		args = append(args, "--config", config)
		var out, diag bytes.Buffer
		if e := run(args, &out, &diag); e != nil {
			t.Fatal(e)
		}
		var report bootstrap.BackupReport
		if e := json.Unmarshal(out.Bytes(), &report); e != nil || report.RestoreReady || report.Files != 3 || report.Applied {
			t.Fatal(report, e)
		}
	}
	keys := filepath.Join(parent, "separate-keys")
	var out, diag bytes.Buffer
	if e = run([]string{"backup", "export-keys", "--input", output, "--output", keys, "--config", config}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	diag.Reset()
	if e = run([]string{"backup", "reclaim-keys", "--input", keys, "--config", config, "--apply"}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var preserved bootstrap.BackupReport
	if e = json.Unmarshal(out.Bytes(), &preserved); e != nil || preserved.Applied || preserved.Expired || preserved.Files != 3 {
		t.Fatal(preserved, e)
	}
	prepareWork := filepath.Join(parent, "prepare-work")
	if e = os.Mkdir(prepareWork, 0700); e != nil {
		t.Fatal(e)
	}
	prepareArgs := []string{"backup", "prepare", "--config", config, "--output", filepath.Join(parent, "prepared-copy"), "--keys-output", filepath.Join(parent, "prepared-keys"), "--work-parent", prepareWork}
	out.Reset()
	if e = run(prepareArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var prepared bootstrap.BackupPreparationReport
	if e = json.Unmarshal(out.Bytes(), &prepared); e != nil || !prepared.Complete || prepared.RestoreReady || prepared.Phase != "complete" || !prepared.Replay.Replayed {
		t.Fatal(prepared, e)
	}
	copyParent, keysParent := filepath.Join(parent, "paired-copies"), filepath.Join(parent, "paired-keys")
	for _, p := range []string{copyParent, keysParent} {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Rename(filepath.Join(parent, "prepared-copy"), filepath.Join(copyParent, "pair")); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(parent, "prepared-keys"), filepath.Join(keysParent, "pair")); e != nil {
		t.Fatal(e)
	}
	// 元の出力先を既存にして従来のpreflight拒否試験を維持する。
	if e = os.Mkdir(filepath.Join(parent, "prepared-copy"), 0700); e != nil {
		t.Fatal(e)
	}
	sweepArgs := []string{"backup", "sweep-expired", "--copy-parent", copyParent, "--keys-parent", keysParent, "--apply"}
	out.Reset()
	if e = run(sweepArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var swept bootstrap.BackupSweepReport
	if e = json.Unmarshal(out.Bytes(), &swept); e != nil || len(swept.Items) != 1 || swept.Items[0].Status != "retained" || swept.RestoreReady {
		t.Fatal(swept, e)
	}
	if e = os.WriteFile(filepath.Join(copyParent, "z-missing-keys"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e = run(sweepArgs, &out, &diag); e == nil {
		t.Fatal("missing bundle accepted")
	}
	if e = json.Unmarshal(out.Bytes(), &swept); e != nil || swept.Rejected != 1 || swept.Next != "z-missing-keys" {
		t.Fatal(swept, e)
	}
	for _, extra := range [][]string{{"--budget", "0s"}, {"--limit", "129"}, {"--after", "../escape"}, {"--config", config}, {"unexpected"}} {
		out.Reset()
		if e = run(append(append([]string{}, sweepArgs...), extra...), &out, &diag); e == nil {
			t.Fatal(extra, "accepted")
		}
	}
	out.Reset()
	if e = run(prepareArgs, &out, &diag); e == nil {
		t.Fatal("existing outputs reused")
	}
	if e = json.Unmarshal(out.Bytes(), &prepared); e != nil || prepared.Complete || prepared.Phase != "preflight" {
		t.Fatal("failure JSON missing", prepared, e)
	}
	for _, extra := range [][]string{{"--budget", "0s"}, {"--budget", "2h"}, {"--apply"}, {"unexpected"}} {
		var invalidOut, invalidDiag bytes.Buffer
		if e = run(append(append([]string{}, prepareArgs...), extra...), &invalidOut, &invalidDiag); e == nil {
			t.Fatal(extra, "accepted")
		}
	}
	trust, plan := filepath.Join(parent, "trust.json"), filepath.Join(parent, "keys-plan.json")
	out.Reset()
	if e = run([]string{"backup", "export-trust", "--config", config, "--output", trust}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var trustReport bootstrap.BackupTrustReport
	if e = json.Unmarshal(out.Bytes(), &trustReport); e != nil || !trustReport.Exported || trustReport.RestoreReady {
		t.Fatal(trustReport, e)
	}
	preparedPlan := filepath.Join(parent, "prepared-plan.json")
	plannedPrepareArgs := append(append([]string{}, prepareArgs...), "--output", filepath.Join(parent, "planned-prepared-copy"), "--keys-output", filepath.Join(parent, "planned-prepared-keys"), "--trust-instance", trust, "--partial-plan", preparedPlan)
	out.Reset()
	if e = run(plannedPrepareArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var plannedPrepared bootstrap.BackupPreparationReport
	if e = json.Unmarshal(out.Bytes(), &plannedPrepared); e != nil || !plannedPrepared.Complete || plannedPrepared.PartialPlanned == nil || !*plannedPrepared.PartialPlanned || !plannedPrepared.Replay.Replayed {
		t.Fatal(plannedPrepared, e)
	}
	out.Reset()
	if e = run(plannedPrepareArgs, &out, &diag); e == nil {
		t.Fatal("planned prepare outputs reused")
	}
	plannedPrepared = bootstrap.BackupPreparationReport{}
	if e = json.Unmarshal(out.Bytes(), &plannedPrepared); e != nil || plannedPrepared.Complete || plannedPrepared.Phase != "preflight" || plannedPrepared.PartialPlanned == nil || *plannedPrepared.PartialPlanned || plannedPrepared.Capture != nil {
		t.Fatal(plannedPrepared, e)
	}
	for _, oneFlag := range [][]string{{"--trust-instance", trust}, {"--partial-plan", preparedPlan}} {
		if e = run(append(append([]string{}, prepareArgs...), oneFlag...), &out, &diag); e == nil {
			t.Fatal("unpaired flags accepted", oneFlag)
		}
	}
	keysPartialPlan := filepath.Join(parent, "prepare-keys-partial-plan.json")
	bothPrepareArgs := append(append([]string{}, plannedPrepareArgs...), "--output", filepath.Join(parent, "both-prepared-copy"), "--keys-output", filepath.Join(parent, "both-prepared-keys"), "--partial-plan", filepath.Join(parent, "both-body-plan.json"), "--partial-keys-plan", keysPartialPlan)
	out.Reset()
	if e = run(bothPrepareArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var both bootstrap.BackupPreparationReport
	if e = json.Unmarshal(out.Bytes(), &both); e != nil || !both.Complete || both.KeysPartialPlanned == nil || !*both.KeysPartialPlanned || !*both.PartialPlanned || !both.Replay.Replayed {
		t.Fatal(both, e)
	}
	if e = run(append(append([]string{}, prepareArgs...), "--partial-keys-plan", keysPartialPlan), &out, &diag); e == nil {
		t.Fatal("keys plan without body plan accepted")
	}
	completePreparePlan := filepath.Join(parent, "prepare-complete-keys-plan.json")
	completePrepareKeys := filepath.Join(parent, "complete-prepared-keys")
	completePrepareArgs := append(append([]string{}, prepareArgs...), "--output", filepath.Join(parent, "complete-prepared-copy"), "--keys-output", completePrepareKeys, "--trust-instance", trust, "--keys-plan", completePreparePlan)
	out.Reset()
	if e = run(completePrepareArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var completePrepared bootstrap.BackupPreparationReport
	if e = json.Unmarshal(out.Bytes(), &completePrepared); e != nil || !completePrepared.Complete || completePrepared.KeysPlanned == nil || !*completePrepared.KeysPlanned || !completePrepared.KeysPlan.Planned || completePrepared.PartialPlanned != nil || completePrepared.KeysPartialPlanned != nil || !completePrepared.Replay.Replayed {
		t.Fatal(completePrepared, e)
	}
	out.Reset()
	if e = run(completePrepareArgs, &out, &diag); e == nil {
		t.Fatal("complete keys plan reused")
	}
	completePrepared = bootstrap.BackupPreparationReport{}
	if e = json.Unmarshal(out.Bytes(), &completePrepared); e != nil || completePrepared.Complete || *completePrepared.KeysPlanned || completePrepared.Phase != "preflight" || completePrepared.KeysPlan != nil {
		t.Fatal(completePrepared, e)
	}
	if e = run(append(append([]string{}, prepareArgs...), "--keys-plan", completePreparePlan), &out, &diag); e == nil {
		t.Fatal("keys plan without trust accepted")
	}
	exportPartialKeys := filepath.Join(parent, "export-planned-keys")
	exportPartialPlan := filepath.Join(parent, "export-partial-keys-plan.json")
	exportPartialArgs := []string{"backup", "export-keys-planned", "--config", config, "--input", output, "--output", exportPartialKeys, "--trust-instance", trust, "--plan", exportPartialPlan}
	out.Reset()
	if e = run(exportPartialArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var exportedPartial bootstrap.PlannedBackupKeysExportReport
	if e = json.Unmarshal(out.Bytes(), &exportedPartial); e != nil || !exportedPartial.Complete || !exportedPartial.Planned || !exportedPartial.Keys.Verified {
		t.Fatal(exportedPartial, e)
	}
	out.Reset()
	if e = run(exportPartialArgs, &out, &diag); e == nil {
		t.Fatal("existing partial keys reused")
	}
	exportedPartial = bootstrap.PlannedBackupKeysExportReport{}
	if e = json.Unmarshal(out.Bytes(), &exportedPartial); e != nil || exportedPartial.Complete || exportedPartial.Planned || exportedPartial.Phase != "preflight" || exportedPartial.Keys != nil {
		t.Fatal(exportedPartial, e)
	}
	reclaimPartialKeysArgs := []string{"backup", "reclaim-keys-partial", "--input", exportPartialKeys, "--trust-instance", trust, "--plan", exportPartialPlan, "--apply"}
	out.Reset()
	if e = run(reclaimPartialKeysArgs, &out, &diag); e == nil {
		t.Fatal("completed keys partial reclaimed")
	}
	var rejectedPartialKeys bootstrap.BackupReport
	if e = json.Unmarshal(out.Bytes(), &rejectedPartialKeys); e != nil || rejectedPartialKeys.Applied || rejectedPartialKeys.Verified {
		t.Fatal(rejectedPartialKeys, e)
	}
	out.Reset()
	if e = run(append(append([]string{}, reclaimPartialKeysArgs...), "--plan", filepath.Join(parent, "missing-keys-plan.json")), &out, &diag); e == nil || !json.Valid(out.Bytes()) {
		t.Fatal("missing partial keys plan failure JSON", e)
	}
	for _, bad := range [][]string{{"--budget", "0s"}, {"--budget", "6m"}, {"--config", config}, {"unexpected"}} {
		if e = run(append(append([]string{}, reclaimPartialKeysArgs...), bad...), &out, &diag); e == nil {
			t.Fatal("invalid partial keys flags accepted", bad)
		}
	}
	partialBodyParent, partialKeysParent := filepath.Join(parent, "partial-bodies"), filepath.Join(parent, "partial-keys")
	partialBodyPlans, partialKeysPlans := filepath.Join(parent, "partial-body-plans"), filepath.Join(parent, "partial-key-plans")
	for _, p := range []string{partialBodyParent, partialKeysParent, partialBodyPlans, partialKeysPlans} {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	for _, args := range [][]string{
		{"backup", "capture-planned", "--config", config, "--output", filepath.Join(partialBodyParent, "one"), "--trust-instance", trust, "--plan", filepath.Join(partialBodyPlans, "one.json")},
		{"backup", "export-keys-planned", "--config", config, "--input", output, "--output", filepath.Join(partialKeysParent, "one"), "--trust-instance", trust, "--plan", filepath.Join(partialKeysPlans, "one.json")},
	} {
		out.Reset()
		if e = run(args, &out, &diag); e != nil {
			t.Fatal(e)
		}
	}
	plannedCopy, partialPlan := filepath.Join(parent, "planned-copy"), filepath.Join(parent, "partial-plan.json")
	partialCaptureArgs := []string{"backup", "capture-planned", "--config", config, "--output", plannedCopy, "--trust-instance", trust, "--plan", partialPlan}
	out.Reset()
	if e = run(partialCaptureArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var partialCapture bootstrap.PlannedBackupCaptureReport
	if e = json.Unmarshal(out.Bytes(), &partialCapture); e != nil || !partialCapture.Planned || !partialCapture.Complete || !partialCapture.Capture.Verified || partialCapture.RestoreReady {
		t.Fatal(partialCapture, e)
	}
	out.Reset()
	if e = run(partialCaptureArgs, &out, &diag); e == nil {
		t.Fatal("planned capture outputs reused")
	}
	if e = json.Unmarshal(out.Bytes(), &partialCapture); e != nil || partialCapture.Complete || partialCapture.Phase != "preflight" {
		t.Fatal(partialCapture, e)
	}
	planArgs := []string{"backup", "plan-keys", "--config", config, "--input", keys, "--trust-instance", trust, "--output", plan}
	out.Reset()
	if e = run(planArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var keyPlan bootstrap.BackupKeysPlanReport
	if e = json.Unmarshal(out.Bytes(), &keyPlan); e != nil || !keyPlan.Planned || keyPlan.RestoreReady {
		t.Fatal(keyPlan, e)
	}
	out.Reset()
	if e = run(planArgs, &out, &diag); e == nil {
		t.Fatal("plan reused")
	}
	if e = json.Unmarshal(out.Bytes(), &keyPlan); e != nil || keyPlan.Planned {
		t.Fatal("plan failure JSON", keyPlan, e)
	}
	planParent := filepath.Join(parent, "key-plans")
	if e = os.Mkdir(planParent, 0700); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e = run([]string{"backup", "plan-keys", "--config", config, "--input", filepath.Join(keysParent, "pair"), "--trust-instance", trust, "--output", filepath.Join(planParent, "pair.json")}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	busy, e := platform.Lock(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"backup", "export-trust", "--config", config, "--output", filepath.Join(parent, "busy-trust.json")}, {"backup", "plan-keys", "--config", config, "--input", keys, "--trust-instance", trust, "--output", filepath.Join(parent, "busy-plan.json")}} {
		out.Reset()
		if e = run(args, &out, &diag); e == nil {
			t.Fatal("busy source accepted")
		}
		var failure map[string]json.RawMessage
		if e = json.Unmarshal(out.Bytes(), &failure); e != nil {
			t.Fatal("busy failure JSON", e)
		}
		if _, e = os.Stat(args[len(args)-1]); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("busy output created", e)
		}
	}
	out.Reset()
	if e = run([]string{"backup", "capture-planned", "--config", config, "--output", filepath.Join(parent, "busy-partial-copy"), "--trust-instance", trust, "--plan", filepath.Join(parent, "busy-partial-plan.json")}, &out, &diag); e == nil {
		t.Fatal("busy partial capture accepted")
	}
	partialCapture = bootstrap.PlannedBackupCaptureReport{}
	if e = json.Unmarshal(out.Bytes(), &partialCapture); e != nil || partialCapture.Complete || partialCapture.Planned || partialCapture.Capture != nil {
		t.Fatal("busy capture JSON", partialCapture, e)
	}
	if e = platform.Unlock(busy); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(config); e != nil {
		t.Fatal(e)
	}
	for _, fixture := range [][4]string{{"body", partialBodyParent, partialBodyPlans, "manifest.json"}, {"keys", partialKeysParent, partialKeysPlans, "bundle.json"}} {
		partialSweepArgs := []string{"backup", "sweep-partial", "--kind", fixture[0], "--root-parent", fixture[1], "--plan-parent", fixture[2], "--trust-instance", trust}
		out.Reset()
		if e = run(append(append([]string{}, partialSweepArgs...), "--apply"), &out, &diag); !errors.Is(e, bootstrap.ErrBackupSweepRejected) {
			t.Fatal("completed partial sweep", e)
		}
		var result struct {
			Kind string `json:"kind"`
			bootstrap.BackupSweepReport
		}
		if e = json.Unmarshal(out.Bytes(), &result); e != nil || result.Kind != fixture[0] || result.Rejected != 1 {
			t.Fatal(result, e)
		}
		if e = os.Rename(filepath.Join(fixture[1], "one", fixture[3]), filepath.Join(parent, "saved-partial-"+fixture[0])); e != nil {
			t.Fatal(e)
		}
		for _, extra := range [][]string{nil, {"--apply"}} {
			out.Reset()
			if e = run(append(append([]string{}, partialSweepArgs...), extra...), &out, &diag); e != nil {
				t.Fatal(e)
			}
			if e = json.Unmarshal(out.Bytes(), &result); e != nil || len(result.Items) != 1 || result.Items[0].Status != "retained" || result.Items[0].Reclaim.Applied {
				t.Fatal(result, e)
			}
		}
		partialWatchArgs := append([]string{"backup", "watch-partial"}, partialSweepArgs[2:]...)
		stop := errors.New("partial watch output stop")
		writer := &watchReportWriter{err: stop}
		if e = run(partialWatchArgs, writer, &diag); !errors.Is(e, stop) {
			t.Fatal(e)
		}
		var watched struct {
			Kind string `json:"kind"`
			bootstrap.BackupMaintenanceReport
		}
		if e = json.Unmarshal(writer.Bytes(), &watched); e != nil || watched.Kind != fixture[0] || watched.Status != "completed" || watched.Sweep.Items[0].Status != "retained" {
			t.Fatal(watched, e)
		}
		out.Reset()
		if e = run(append(append([]string{}, partialSweepArgs...), "--after", "one"), &out, &diag); e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(out.Bytes(), &result); e != nil || len(result.Items) != 0 {
			t.Fatal(result, e)
		}
		if e = os.Rename(filepath.Join(fixture[2], "one.json"), filepath.Join(parent, "saved-plan-"+fixture[0])); e != nil {
			t.Fatal(e)
		}
		out.Reset()
		if e = run(partialSweepArgs, &out, &diag); !errors.Is(e, bootstrap.ErrBackupSweepRejected) {
			t.Fatal(e)
		}
		if e = json.Unmarshal(out.Bytes(), &result); e != nil || result.Rejected != 1 || result.Next != "one" {
			t.Fatal(result, e)
		}
		if e = os.Rename(filepath.Join(parent, "saved-plan-"+fixture[0]), filepath.Join(fixture[2], "one.json")); e != nil {
			t.Fatal(e)
		}
		for _, args := range [][]string{partialSweepArgs, partialWatchArgs} {
			for _, extra := range [][]string{{"--kind", "unknown"}, {"--config", config}, {"--limit", "129"}, {"--budget", "0s"}, {"unexpected"}} {
				if e = run(append(append([]string{}, args...), extra...), &out, &diag); e == nil {
					t.Fatal("partial flags accepted", extra)
				}
			}
		}
	}
	partialReclaimArgs := []string{"backup", "reclaim-partial", "--input", plannedCopy, "--trust-instance", trust, "--plan", partialPlan}
	out.Reset()
	if e = run(append(append([]string{}, partialReclaimArgs...), "--apply"), &out, &diag); e == nil {
		t.Fatal("completed copy reclaimed as partial")
	}
	var partialReport bootstrap.BackupReport
	if e = json.Unmarshal(out.Bytes(), &partialReport); e != nil || partialReport.Applied || partialReport.Verified {
		t.Fatal(partialReport, e)
	}
	// 完成印欠落を模擬し、正本/設定なしでも期限内は保持する。
	if e = os.Rename(filepath.Join(plannedCopy, "manifest.json"), filepath.Join(parent, "saved-planned-manifest.json")); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e = run(append(append([]string{}, partialReclaimArgs...), "--apply"), &out, &diag); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(out.Bytes(), &partialReport); e != nil || partialReport.Expired || partialReport.Applied || partialReport.Verified {
		t.Fatal(partialReport, e)
	}
	out.Reset()
	if e = run(append(append([]string{}, partialReclaimArgs...), "--plan", filepath.Join(parent, "missing-partial.json")), &out, &diag); e == nil || !json.Valid(out.Bytes()) {
		t.Fatal("partial failure JSON", e)
	}
	for _, args := range [][]string{partialCaptureArgs, partialReclaimArgs} {
		for _, extra := range [][]string{{"--budget", "0s"}, {"--budget", "6m"}, {"unexpected"}} {
			if e = run(append(append([]string{}, args...), extra...), &out, &diag); e == nil {
				t.Fatal(extra, "accepted")
			}
		}
	}
	if e = run(append(append([]string{}, partialReclaimArgs...), "--config", config), &out, &diag); e == nil {
		t.Fatal("partial reclaim config accepted")
	}
	out.Reset()
	if e = run([]string{"backup", "reclaim-keys-planned", "--input", completePrepareKeys, "--trust-instance", trust, "--plan", completePreparePlan, "--apply"}, &out, &diag); e != nil {
		t.Fatal("prepared complete key plan without source", e)
	}
	var completePlanRetained bootstrap.BackupReport
	if e = json.Unmarshal(out.Bytes(), &completePlanRetained); e != nil || completePlanRetained.Applied || completePlanRetained.Expired {
		t.Fatal(completePlanRetained, e)
	}
	keyReclaimArgs := []string{"backup", "reclaim-keys-planned", "--input", keys, "--trust-instance", trust, "--plan", plan, "--apply"}
	out.Reset()
	if e = run(keyReclaimArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var keyRetained bootstrap.BackupReport
	if e = json.Unmarshal(out.Bytes(), &keyRetained); e != nil || keyRetained.Applied || keyRetained.Expired || keyRetained.Verified {
		t.Fatal(keyRetained, e)
	}
	badReclaim := append(append([]string{}, keyReclaimArgs...), "--plan", filepath.Join(parent, "missing-plan.json"))
	out.Reset()
	if e = run(badReclaim, &out, &diag); e == nil {
		t.Fatal("missing plan accepted")
	}
	var failureJSON map[string]json.RawMessage
	if e = json.Unmarshal(out.Bytes(), &failureJSON); e != nil {
		t.Fatal("preauthentication failure JSON", e)
	}
	for _, extra := range [][]string{{"--config", config}, {"--budget", "0s"}, {"--budget", "6m"}, {"unexpected"}} {
		out.Reset()
		if e = run(append(append([]string{}, keyReclaimArgs...), extra...), &out, &diag); e == nil {
			t.Fatal(extra, "accepted")
		}
	}
	keySweepArgs := []string{"backup", "sweep-keys-planned", "--keys-parent", keysParent, "--plan-parent", planParent, "--trust-instance", trust}
	for _, extra := range [][]string{nil, {"--apply"}} {
		out.Reset()
		if e = run(append(append([]string{}, keySweepArgs...), extra...), &out, &diag); e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(out.Bytes(), &swept); e != nil || len(swept.Items) != 1 || swept.Items[0].Status != "retained" || swept.Items[0].Reclaim.Applied {
			t.Fatal(swept, e)
		}
	}
	if e = os.Rename(filepath.Join(planParent, "pair.json"), filepath.Join(planParent, "missing.json")); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e = run(append(append([]string{}, keySweepArgs...), "--apply"), &out, &diag); !errors.Is(e, bootstrap.ErrBackupSweepRejected) {
		t.Fatal(e)
	}
	if e = json.Unmarshal(out.Bytes(), &swept); e != nil || swept.Rejected != 1 || swept.Next != "pair" {
		t.Fatal(swept, e)
	}
	keyWatchArgs := append([]string{"backup", "watch-keys-planned"}, keySweepArgs[2:]...)
	keyStop := errors.New("key watch output stopped")
	keyWatchOut := &watchReportWriter{err: keyStop}
	if e = run(keyWatchArgs, keyWatchOut, &diag); !errors.Is(e, keyStop) {
		t.Fatal(e)
	}
	var keyWatched bootstrap.BackupMaintenanceReport
	if e = json.Unmarshal(keyWatchOut.Bytes(), &keyWatched); e != nil || keyWatched.Status != "needs_attention" || keyWatched.Pass != 1 || keyWatched.Sweep.Rejected != 1 {
		t.Fatal(keyWatched, e)
	}
	if e = os.Rename(filepath.Join(planParent, "missing.json"), filepath.Join(planParent, "pair.json")); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{keySweepArgs, keyWatchArgs} {
		for _, extra := range [][]string{{"--config", config}, {"--limit", "129"}, {"--budget", "0s"}, {"--budget", "6m"}, {"unexpected"}} {
			out.Reset()
			if e = run(append(append([]string{}, args...), extra...), &out, &diag); e == nil {
				t.Fatal(extra, "accepted")
			}
		}
	}
	for _, extra := range [][]string{{"--interval", "0s"}, {"--interval", "25h"}, {"--after", "pair"}} {
		if e = run(append(append([]string{}, keyWatchArgs...), extra...), &out, &diag); e == nil {
			t.Fatal(extra, "accepted")
		}
	}
	watchArgs := []string{"backup", "watch-expired", "--copy-parent", copyParent, "--keys-parent", keysParent}
	stop := errors.New("expired watch output stopped")
	watchOut := &watchReportWriter{err: stop}
	if e = run(watchArgs, watchOut, &diag); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	var watched bootstrap.BackupMaintenanceReport
	if e = json.Unmarshal(watchOut.Bytes(), &watched); e != nil || watched.Status != "needs_attention" || watched.Apply || watched.Pass != 1 || watched.Sweep.Items[0].Status != "retained" || watched.Sweep.Rejected != 1 {
		t.Fatal(watched, e)
	}
	for _, extra := range [][]string{{"--interval", "0s"}, {"--interval", "25h"}, {"--budget", "0s"}, {"--budget", "6m"}, {"--limit", "129"}, {"--after", "pair"}, {"--config", config}, {"unexpected"}} {
		out.Reset()
		if e = run(append(append([]string{}, watchArgs...), extra...), &out, &diag); e == nil {
			t.Fatal(extra, "accepted")
		}
	}
	out.Reset()
	diag.Reset()
	if e = run([]string{"backup", "verify-with-keys", "--input", output, "--keys", keys}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var verified bootstrap.BackupReport
	if e = json.Unmarshal(out.Bytes(), &verified); e != nil || !verified.Verified || verified.RestoreReady {
		t.Fatal(verified, e)
	}

	work := filepath.Join(parent, "work")
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	diag.Reset()
	if e = run([]string{"backup", "verify-replay", "--input", output, "--keys", keys, "--work-parent", work}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(out.Bytes(), &verified); e != nil || !verified.Verified || !verified.Replayed || verified.RestoreReady {
		t.Fatal(verified, e)
	}
	files, e := os.ReadDir(work)
	// 親の排他inodeを維持し、再生payloadが残っていないことを確認する。
	if e != nil || len(files) != 1 || len(files) == 1 && files[0].Name() != ".lock" {
		t.Fatal(files, e)
	}
	for _, args := range [][]string{{"backup"}, {"backup", "restore"}, {"backup", "verify-replay", "--input", output, "--keys", keys}, {"backup", "verify-replay", "--input", output, "--keys", keys, "--work-parent", work, "--config", config}, {"backup", "verify-with-keys", "--input", output}, {"backup", "verify-with-keys", "--input", output, "--keys", keys, "--config", config}, {"backup", "export-keys", "--input", output, "--config", config}, {"backup", "capture", "--config", config}, {"backup", "capture", "--config", config, "--output", filepath.Join(cfg.DataDir, "inside")}, {"backup", "verify", "--input", output, "--config", config, "--apply"}} {
		var out, diag bytes.Buffer
		if e := run(args, &out, &diag); e == nil || out.Len() != 0 {
			t.Fatal(args, e, out.String())
		}
	}
}
