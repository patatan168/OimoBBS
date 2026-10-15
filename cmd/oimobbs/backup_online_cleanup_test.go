// 作成処理を伴わないオンライン期限回収CLIのプレビューと引数拒否を検査する。
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/bootstrap"
)

func TestOnlineBackupCleanupCLI(t *testing.T) {
	cfg, path := requiredGCCLIConfig(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := func(name string) string {
		p := filepath.Join(parent, name)
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	options := bootstrap.OnlineBackupConfig{CopyParent: directory("copies"), KeysParent: directory("keys"), PartialPlanParent: directory("partial"), PartialKeysPlanParent: directory("partial-keys"), KeysPlanParent: directory("keys-plan"), PairPlanParent: directory("pairs"), WorkParent: directory("work"), ControlParent: directory("control"), TrustInstance: filepath.Join(parent, "trust.json"), IntervalSeconds: 3600, BudgetSeconds: 30}
	trust, err := os.ReadFile(filepath.Join(cfg.DataDir, "instance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(options.TrustInstance, trust, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(options)
	settings := filepath.Join(parent, "backup.json")
	if err = os.WriteFile(settings, raw, 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"backup", "sweep-online", "--config", path, "--online-backup-config", settings}
	for _, extra := range [][]string{nil, {"--apply"}} {
		var out, diagnostics bytes.Buffer
		args := append(append([]string{}, base...), extra...)
		if err := run(args, &out, &diagnostics); err != nil {
			t.Fatal(err, diagnostics.String(), out.String())
		}
		var report bootstrap.OnlineBackupSweepReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Rejected != 0 || report.More || report.ReplayPending || len(report.Items) != 0 {
			t.Fatal(report, err)
		}
	}
	for _, extra := range [][]string{{"--limit", "0"}, {"--limit", "129"}, {"extra"}, {"--after", "../other"}} {
		var out, diagnostics bytes.Buffer
		args := append(append([]string{}, base...), extra...)
		if err := run(args, &out, &diagnostics); err == nil {
			t.Fatal("invalid cleanup accepted", extra)
		}
	}
	// 署名計画のない出力はapplyでも残し、部分結果と非zero終了を同時に返す。
	unknown := filepath.Join(options.CopyParent, "unknown")
	if err := os.Mkdir(unknown, 0700); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	if err := run(append(append([]string{}, base...), "--apply"), &out, &diagnostics); err == nil {
		t.Fatal("unknown output was accepted")
	}
	var report bootstrap.OnlineBackupSweepReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Rejected != 1 || len(report.Items) != 1 || report.Items[0].Status != "rejected" {
		t.Fatal(report, err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatal("unknown output disappeared", err)
	}
}
