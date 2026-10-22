// CLIの成功出力、再実行拒否、未実装コマンドの失敗を検証する。
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInitCheckCLI(t *testing.T) {
	dir := t.TempDir()
	raw := `{"schema_version":1,"edge":null,"maintenance":null,"auto_reports":null,"data_dir":"data","public":{"listen":"127.0.0.1:9080","base_url":"http://127.0.0.1:9080","tls_cert_file":"","tls_key_file":""},"admin":{"listen":"127.0.0.1:9081","transport":"loopback_tunnel","origin":"http://127.0.0.1:9081"},"trusted_proxies":[],"egress_budget_bits_per_second":80000000}`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	var original string
	for _, action := range []string{"init", "check"} {
		var out, diag bytes.Buffer
		if err := run([]string{action, "--config", path}, &out, &diag); err != nil {
			t.Fatal(err)
		}
		var report map[string]any
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report["status"] != "bootstrap_valid" || len(report) != 7 {
			t.Fatal("unexpected report", report)
		}
		if action == "init" {
			original = out.String()
		} else if out.String() != original {
			t.Fatal("identity changed")
		}
	}
	for _, args := range [][]string{{"init", "--config", path}, {"serve", "--config", path}, {"check", "--config", path, "unexpected"}} {
		var out, diag bytes.Buffer
		if err := run(args, &out, &diag); err == nil || out.Len() != 0 {
			t.Fatal("failure emitted successful output", args)
		}
	}
}
