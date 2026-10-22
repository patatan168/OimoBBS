// 候補CLIの誤操作・移管未完・稼働中の排他で成功出力を返さないことを検証する。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"testing"
)

func TestControlSnapshotCLIBoundaries(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../config.local.example.json")
	if e != nil {
		t.Fatal(e)
	}
	var value map[string]any
	if e = json.Unmarshal(raw, &value); e != nil {
		t.Fatal(e)
	}
	value["data_dir"] = "data"
	raw, _ = json.Marshal(value)
	config := filepath.Join(parent, "config.json")
	if e = os.WriteFile(config, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var out, diag bytes.Buffer
	if e = run([]string{"init", "--config", config}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(parent, "candidate")
	cases := [][]string{{"control", "enable-snapshots", "--config", config}, {"control", "activate-snapshot", "--config", config, "--input", output}, {"control"}, {"control", "activate"}, {"control", "prepare-snapshot", "--config", config}, {"control", "prepare-snapshot", "--config", config, "--output", output}, {"control", "verify-snapshot", "--config", config, "--input", output}, {"control", "prepare-snapshot", "--output", output, "extra"}}
	for _, args := range cases {
		out.Reset()
		if e = run(args, &out, &diag); e == nil || out.Len() != 0 {
			t.Fatal("invalid success", args, e)
		}
	}
	if _, e = os.Stat(output); !os.IsNotExist(e) {
		t.Fatal("candidate created without audit proof")
	}
	cfg, e := bootstrap.LoadConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	repo, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	out.Reset()
	if e = run([]string{"control", "prepare-snapshot", "--config", config, "--output", output}, &out, &diag); e == nil || out.Len() != 0 {
		t.Fatal("live data lock bypassed")
	}
}

func TestControlSnapshotCLIActivation(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "data"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:8080", BaseURL: "http://127.0.0.1:8080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:8081", Origin: "http://127.0.0.1:8081", Transport: "loopback_tunnel"}, TrustedProxies: []string{}, EgressBits: 80000000}
	if _, err := bootstrap.Initialize(cfg, "切替CLI"); err != nil {
		t.Fatal(err)
	}
	r, err := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ConfigureAdministrator("owner", "所有者", "test-control-activation-password", false); err != nil {
		r.Close()
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.CreateBoard(context.Background(), "news", "ニュース"); err != nil {
		r.Close()
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(parent, "config.json")
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(parent, "candidate")
	for _, args := range [][]string{
		{"enable-snapshots", "--config", config},
		{"prepare-snapshot", "--config", config, "--output", input},
		{"verify-snapshot", "--config", config, "--input", input},
		{"activate-snapshot", "--config", config, "--input", input},
		{"activate-snapshot", "--config", config, "--input", input},
		{"reclaim-wal", "--config", config},
		{"reclaim-wal", "--config", config, "--apply"},
		{"reclaim-wal", "--config", config, "--apply"},
	} {
		var out, diag bytes.Buffer
		if err = runControl(args, &out, &diag); err != nil {
			t.Fatal(args[0], err)
		}
		var result map[string]any
		if err = json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if args[0] == "reclaim-wal" && result["applied"] != (len(args) == 4) {
			t.Fatal("incorrect reclaim result", out.String())
		}
		if args[0] == "activate-snapshot" && result["activated"] != true {
			t.Fatal("activation not reported", out.String())
		}
	}
}

// 更新候補CLIはsnapshot化・旧WAL回収後の保存先でも再照合できる。
func TestAuditRetentionCLI(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../config.local.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["data_dir"] = "data"
	raw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(parent, "config.json")
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	if err = run([]string{"init", "--config", config}, &out, &diag); err != nil {
		t.Fatal(err)
	}
	actual, err := bootstrap.LoadConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	r, err := bootstrap.OpenPostingRepository(actual, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ConfigureAdministrator("owner", "所有者", "audit-retention-cli-password", false); err != nil {
		r.Close()
		t.Fatal(err)
	}
	r.Close()
	snapshot := filepath.Join(parent, "snapshot")
	candidate := filepath.Join(parent, "retention")
	for _, args := range [][]string{
		{"control", "enable-snapshots", "--config", config},
		{"control", "prepare-snapshot", "--config", config, "--output", snapshot},
		{"control", "activate-snapshot", "--config", config, "--input", snapshot},
		{"control", "reclaim-wal", "--config", config, "--apply"},
		{"audit", "prepare-retention", "--config", config, "--output", candidate},
		{"audit", "verify-retention", "--config", config, "--input", candidate},
		{"audit", "apply-retention", "--config", config, "--input", candidate},
		{"audit", "apply-retention", "--config", config, "--input", candidate},
	} {
		out.Reset()
		if err = run(args, &out, &diag); err != nil {
			t.Fatal(args, err)
		}
		if args[0] == "audit" {
			var result bootstrap.AuditRetentionReport
			if err = json.Unmarshal(out.Bytes(), &result); err != nil || !result.Verified || result.Applied != (args[1] == "apply-retention") {
				t.Fatal(result, err)
			}
		}
	}
	for _, apply := range []bool{false, true, true} {
		args := []string{"audit", "reclaim-days", "--config", config}
		if apply {
			args = append(args, "--apply")
		}
		out.Reset()
		if err = run(args, &out, &diag); err != nil {
			t.Fatal(err)
		}
		var result bootstrap.AuditReclaimReport
		if err = json.Unmarshal(out.Bytes(), &result); err != nil || !result.Verified || result.Applied != apply || result.Days != 0 {
			t.Fatal(result, err)
		}
	}

}
