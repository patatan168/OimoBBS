// 実保存先で原本回収の有効化と再送・起動検査を通す。
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/bootstrap"
	"oimobbs/internal/postcapture"
)

func TestRequiredGCEnableCLI(t *testing.T) {
	cfg, path := requiredGCCLIConfig(t)
	for range 2 {
		var out, diagnostics bytes.Buffer
		if e := run([]string{"logs", "enable-required-gc", "--config", path}, &out, &diagnostics); e != nil {
			t.Fatal(e)
		}
		if out.String() != "{\"enabled\":true,\"required_reader_version\":48}\n" {
			t.Fatal("unexpected enable report", out.String())
		}
		report, e := bootstrap.Check(cfg)
		if e != nil {
			t.Fatal(e)
		}
		if report.MinimumReader != 48 {
			t.Fatal("reader floor missing", report)
		}
	}
	for _, args := range [][]string{{"logs"}, {"logs", "unknown"}, {"logs", "enable-required-gc", "--config", path, "extra"}} {
		var out, diagnostics bytes.Buffer
		if e := run(args, &out, &diagnostics); e == nil || out.Len() != 0 {
			t.Fatal("invalid command reported success", args)
		}
	}
}

// requiredGCCLIConfig は管理者を耐久保存した停止中サイトを作る。
func requiredGCCLIConfig(t *testing.T) (bootstrap.Config, string) {
	t.Helper()
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "data"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:8080", BaseURL: "http://127.0.0.1:8080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:8081", Origin: "http://127.0.0.1:8081", Transport: "loopback_tunnel"}, TrustedProxies: []string{}, EgressBits: 80000000}
	if _, e := bootstrap.Initialize(cfg, "GC CLI"); e != nil {
		t.Fatal(e)
	}
	r, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	_, configureErr := r.ConfigureAdministrator("owner", "所有者", "required-gc-cli-password", false)
	closeErr := r.Close()
	if configureErr != nil {
		t.Fatal(configureErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	raw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(parent, "config.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return cfg, path
}
