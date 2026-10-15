// 完成ペアCLIの設定不要回収・失敗JSON・引数拒否を検証する。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/bootstrap"
)

func TestBackupPairCLI(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "data"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:8080", BaseURL: "http://127.0.0.1:8080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:8081", Origin: "http://127.0.0.1:8081", Transport: "loopback_tunnel"}, TrustedProxies: []string{}, CacheBytes: 268435456, EgressBits: 80000000}
	if _, e := bootstrap.Initialize(cfg, "pair CLI"); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	body, keys, trust, plan := filepath.Join(parent, "body"), filepath.Join(parent, "keys"), filepath.Join(parent, "trust.json"), filepath.Join(parent, "plan.json")
	if _, e := bootstrap.CaptureOfflineBackup(ctx, cfg, body); e != nil {
		t.Fatal(e)
	}
	if _, e := bootstrap.ExportBackupKeys(ctx, cfg, body, keys); e != nil {
		t.Fatal(e)
	}
	if _, e := bootstrap.ExportBackupTrust(ctx, cfg, trust); e != nil {
		t.Fatal(e)
	}
	config := filepath.Join(parent, "config.json")
	raw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(config, raw, 0600); e != nil {
		t.Fatal(e)
	}
	common := []string{"--input", body, "--keys", keys, "--trust-instance", trust, "--plan", plan}
	var out, diag bytes.Buffer
	runAction := func(action string, extra ...string) error {
		out.Reset()
		diag.Reset()
		args := append([]string{"backup", action}, common...)
		return run(append(args, extra...), &out, &diag)
	}
	if e = runAction("plan-pair", "--config", config); e != nil {
		t.Fatal(e)
	}
	var report bootstrap.BackupPairReport
	if e = json.Unmarshal(out.Bytes(), &report); e != nil || !report.Planned || report.Body.ID != report.Keys.ID {
		t.Fatal(report, e)
	}
	if e = runAction("plan-pair", "--config", config); e == nil || !json.Valid(out.Bytes()) {
		t.Fatal("duplicate plan JSON", e, out.String())
	}
	work := filepath.Join(parent, "work")
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	preparedBody, preparedKeys, preparedPlan := filepath.Join(parent, "prepared-body"), filepath.Join(parent, "prepared-keys"), filepath.Join(parent, "prepared-pair.json")
	prepareArgs := []string{"backup", "prepare", "--config", config, "--output", preparedBody, "--keys-output", preparedKeys, "--work-parent", work, "--trust-instance", trust, "--pair-plan", preparedPlan}
	out.Reset()
	if e = run(prepareArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var prepared bootstrap.BackupPreparationReport
	if e = json.Unmarshal(out.Bytes(), &prepared); e != nil || !prepared.Complete || prepared.PairPlanned == nil || !*prepared.PairPlanned || !prepared.PairPlan.Planned || prepared.PairPlan.Body.ID != prepared.Capture.ID || prepared.PartialPlanned != nil || !prepared.Replay.Replayed {
		t.Fatal(prepared, e)
	}
	out.Reset()
	if e = run(prepareArgs, &out, &diag); e == nil || !json.Valid(out.Bytes()) {
		t.Fatal("prepare duplicate JSON", e, out.String())
	}
	prepared = bootstrap.BackupPreparationReport{}
	if e = json.Unmarshal(out.Bytes(), &prepared); e != nil || prepared.Complete || prepared.PairPlanned == nil || *prepared.PairPlanned || prepared.Capture != nil {
		t.Fatal(prepared, e)
	}
	if e = run([]string{"backup", "prepare", "--pair-plan", preparedPlan}, &out, &diag); e == nil {
		t.Fatal("pair plan without trust allowed")
	}
	registeredBody, registeredKeys, registeredPair := filepath.Join(parent, "registered-body"), filepath.Join(parent, "registered-keys"), filepath.Join(parent, "registered-pair.json")
	bodyPlan, keyPartial, keyComplete := filepath.Join(parent, "registered-body-partial.json"), filepath.Join(parent, "registered-key-partial.json"), filepath.Join(parent, "registered-key-complete.json")
	out.Reset()
	if e = run([]string{"backup", "prepare", "--config", config, "--output", registeredBody, "--keys-output", registeredKeys, "--work-parent", work, "--trust-instance", trust, "--pair-plan", registeredPair, "--partial-plan", bodyPlan, "--partial-keys-plan", keyPartial, "--keys-plan", keyComplete}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	prepared = bootstrap.BackupPreparationReport{}
	if e = json.Unmarshal(out.Bytes(), &prepared); e != nil || !prepared.Complete || prepared.PairPlan.RelatedPlanCount == nil || *prepared.PairPlan.RelatedPlanCount != 3 {
		t.Fatal(prepared, e)
	}
	standalone := filepath.Join(parent, "registered-standalone.json")
	out.Reset()
	if e = run([]string{"backup", "plan-pair", "--config", config, "--input", registeredBody, "--keys", registeredKeys, "--trust-instance", trust, "--plan", standalone, "--partial-plan", bodyPlan, "--partial-keys-plan", keyPartial, "--keys-plan", keyComplete}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	report = bootstrap.BackupPairReport{}
	if e = json.Unmarshal(out.Bytes(), &report); e != nil || !report.Planned || *report.RelatedPlanCount != 3 {
		t.Fatal(report, e)
	}
	pairBodies, pairKeys, pairPlans := filepath.Join(parent, "pair-bodies"), filepath.Join(parent, "pair-keys"), filepath.Join(parent, "pair-plans")
	for _, p := range []string{pairBodies, pairKeys, pairPlans} {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	out.Reset()
	if e = run([]string{"backup", "prepare", "--config", config, "--output", filepath.Join(pairBodies, "one"), "--keys-output", filepath.Join(pairKeys, "one"), "--work-parent", work, "--trust-instance", trust, "--pair-plan", filepath.Join(pairPlans, "one.json")}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-gone"); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(config); e != nil {
		t.Fatal(e)
	}
	if e = runAction("reclaim-pair", "--apply"); e != nil {
		t.Fatal(e)
	}
	report = bootstrap.BackupPairReport{}
	if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.Expired || report.Applied || report.BodyRemoved || report.RestoreReady || report.Phase != "retained" {
		t.Fatal(report, e)
	}
	out.Reset()
	if e = run([]string{"backup", "reclaim-pair", "--input", preparedBody, "--keys", preparedKeys, "--trust-instance", trust, "--plan", preparedPlan, "--apply"}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	if !json.Valid(out.Bytes()) {
		t.Fatal(out.String())
	}
	registeredArgs := []string{"backup", "reclaim-pair", "--input", registeredBody, "--keys", registeredKeys, "--trust-instance", trust, "--plan", registeredPair, "--apply"}
	out.Reset()
	if e = run(registeredArgs, &out, &diag); e != nil {
		t.Fatal(e)
	}
	report = bootstrap.BackupPairReport{}
	if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.Applied || *report.RelatedPlanCount != 3 || *report.RelatedRetiredCount != 0 {
		t.Fatal(report, e)
	}
	if e = os.Rename(keyComplete, keyComplete+"-missing"); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e = run(registeredArgs, &out, &diag); e == nil || !json.Valid(out.Bytes()) {
		t.Fatal("missing related plan failure JSON", e, out.String())
	}
	if _, e = os.Stat(filepath.Join(registeredBody, "manifest.json")); e != nil {
		t.Fatal("missing related plan deleted body", e)
	}
	if e = os.Rename(keyComplete+"-missing", keyComplete); e != nil {
		t.Fatal(e)
	}
	pairSweepArgs := []string{"backup", "sweep-pairs", "--copy-parent", pairBodies, "--keys-parent", pairKeys, "--plan-parent", pairPlans, "--trust-instance", trust}
	for _, extra := range [][]string{nil, {"--apply"}} {
		out.Reset()
		if e = run(append(append([]string{}, pairSweepArgs...), extra...), &out, &diag); e != nil {
			t.Fatal(e)
		}
		var swept bootstrap.BackupPairSweepReport
		if e = json.Unmarshal(out.Bytes(), &swept); e != nil || len(swept.Items) != 1 || swept.Items[0].Status != "retained" || swept.Items[0].Pair.Applied {
			t.Fatal(swept, e)
		}
	}
	if e = os.Mkdir(filepath.Join(pairBodies, "orphan"), 0700); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e = run(pairSweepArgs, &out, &diag); e == nil || !json.Valid(out.Bytes()) {
		t.Fatal("orphan failure JSON", e, out.String())
	}
	writerStop := errors.New("pair watch writer stop")
	pairWatchArgs := append([]string{"backup", "watch-pairs"}, pairSweepArgs[2:]...)
	if e = run(pairWatchArgs, &watchReportWriter{err: writerStop}, &diag); !errors.Is(e, writerStop) {
		t.Fatal(e)
	}
	for _, bad := range [][]string{{"--config", config}, {"--limit", "129"}, {"--after", "../escape"}, {"--budget", "0s"}} {
		out.Reset()
		if e = run(append(append([]string{}, pairSweepArgs...), bad...), &out, &diag); e == nil {
			t.Fatal(bad)
		}
	}
	for _, extra := range [][]string{{"--config", config}, {"--keys-plan", keyComplete}, {"--budget", "0s"}, {"--budget", "6m"}, {"unexpected"}} {
		if e = runAction("reclaim-pair", extra...); e == nil {
			t.Fatal("invalid args", extra)
		}
	}
	if e = os.WriteFile(plan, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = runAction("reclaim-pair", "--apply"); e == nil || !json.Valid(out.Bytes()) {
		t.Fatal("failure JSON", e, out.String())
	}
	report = bootstrap.BackupPairReport{}
	if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.Body != nil || report.Keys != nil || report.Applied {
		t.Fatal(report, e)
	}
	if e = run([]string{"backup", "reclaim-pair"}, &out, &diag); e == nil {
		t.Fatal("missing fields")
	}
}
