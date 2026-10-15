// 停止中照合CLIの未移管表示・失敗終了と、稼働中データの排他を検証する。
package main

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditVerifyCLI(t *testing.T) {
	dir := t.TempDir()
	raw, e := os.ReadFile("../../config.example.json")
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = json.Unmarshal(raw, &cfg); e != nil {
		t.Fatal(e)
	}
	cfg["data_dir"] = "data"
	raw, e = json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "config.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var out, diag bytes.Buffer
	if e = run([]string{"init", "--config", path}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e = run([]string{"audit", "verify-transfer", "--config", path}, &out, &diag); e == nil {
		t.Fatal("unimported success")
	}
	var report bootstrap.AuditTransferReport
	if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.Complete || len(report.Owners) != 1 {
		t.Fatal(report, e)
	}
	actual, e := bootstrap.LoadConfig(path)
	if e != nil {
		t.Fatal(e)
	}
	repo, e := bootstrap.OpenPostingRepository(actual, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	out.Reset()
	if e = run([]string{"audit", "verify-transfer", "--config", path}, &out, &diag); e == nil || out.Len() != 0 {
		t.Fatal("live owner bypass", e)
	}
	for _, args := range [][]string{{"audit"}, {"audit", "purge"}, {"audit", "verify-transfer", "extra"}} {
		if e = run(args, &out, &diag); e == nil {
			t.Fatal("invalid CLI", args)
		}
	}
}
