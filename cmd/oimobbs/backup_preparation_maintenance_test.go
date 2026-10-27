// 定期作成CLIの確認既定・4計画作成・使用中延期・失敗JSON・引数制約を検証する。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/platform"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupPreparationMaintenanceCLI(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "data"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:8080", BaseURL: "http://127.0.0.1:8080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:8081", Origin: "http://127.0.0.1:8081", Transport: "loopback_tunnel"}, TrustedProxies: []string{}, EgressBits: 80000000}
	if _, e := bootstrap.Initialize(cfg, "preparation CLI"); e != nil {
		t.Fatal(e)
	}
	trust := filepath.Join(parent, "trust.json")
	if _, e := bootstrap.ExportBackupTrust(context.Background(), cfg, trust); e != nil {
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
	flags := []string{"--config", config, "--trust-instance", trust}
	for _, flag := range []string{"copy-parent", "keys-parent", "partial-plan-parent", "partial-keys-plan-parent", "keys-plan-parent", "pair-plan-parent", "work-parent", "control-parent"} {
		path := filepath.Join(parent, flag)
		if e := os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		flags = append(flags, "--"+flag, path)
	}
	var out, diag bytes.Buffer
	runAction := func(action string, extra ...string) error {
		out.Reset()
		diag.Reset()
		args := append([]string{"backup", action}, flags...)
		return run(append(args, extra...), &out, &diag)
	}
	var report bootstrap.BackupPreparationMaintenanceReport
	if e = runAction("prepare-next"); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.Status != "preview" || report.Name != "" {
		t.Fatal(report, e)
	}
	lock, e := platform.Lock(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	if e = runAction("prepare-next", "--apply"); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.Status != "deferred_busy" {
		t.Fatal(report, e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	if e = runAction("prepare-next", "--apply"); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.Status != "completed" || !report.Preparation.Complete || report.RestoreReady {
		t.Fatal(report, e)
	}
	first := report.Name
	if _, e = bootstrap.VerifyBackupWithKeys(context.Background(), filepath.Join(parent, "copy-parent", first), filepath.Join(parent, "keys-parent", first)); e != nil {
		t.Fatal(e)
	}
	stop := errors.New("writer stop")
	e = run(append([]string{"backup", "watch-prepare"}, flags...), &watchReportWriter{err: stop}, &diag)
	if !errors.Is(e, stop) {
		t.Fatal(e)
	}
	for _, extra := range [][]string{{"--budget", "0s"}, {"--budget", "2h"}, {"--copy-parent", cfg.DataDir}, {"--output", "/tmp/unsupported"}} {
		if e = runAction("prepare-next", extra...); e == nil {
			t.Fatal(extra)
		}
	}
	if e = runAction("prepare-next", "--budget", "0s"); e == nil || !json.Valid(out.Bytes()) {
		t.Fatal("failure JSON", e, out.String())
	}
	if e = runAction("watch-prepare", "--interval", "1m"); e == nil {
		t.Fatal("short interval")
	}
}
