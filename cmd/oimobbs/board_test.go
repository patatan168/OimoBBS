// 永続板CLIの作成・別呼出しの一覧・再実行を検証する。
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBoardCLI(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile("../../config.example.json")
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
	path := filepath.Join(dir, "config.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func(args ...string) string {
		t.Helper()
		var out, diag bytes.Buffer
		if err := run(args, &out, &diag); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	invoke("init", "--config", path)
	first := invoke("board", "create", "--config", path, "--key", "news", "--name", "ニュース")
	if got := invoke("board", "create", "--config", path, "--key", "news", "--name", "ニュース"); got != first {
		t.Fatal("retry differs")
	}
	var rows []map[string]any
	if err = json.Unmarshal([]byte(invoke("board", "list", "--config", path)), &rows); err != nil || len(rows) != 1 || rows[0]["name"] != "ニュース" {
		t.Fatal(rows, err)
	}
	invoke("board", "recover", "--config", path)
	invoke("check", "--config", path)
	var out, diag bytes.Buffer
	if err = run([]string{"board", "create", "--config", path, "--key", "news", "--name", "different"}, &out, &diag); err == nil || out.Len() != 0 {
		t.Fatal("conflicting create succeeded")
	}
	policy := invoke("admission", "enable", "--config", path)
	if second := invoke("admission", "enable", "--config", path); second != policy {
		t.Fatal("admission activation reset")
	}
	invoke("check", "--config", path)
	invoke("board", "list", "--config", path, "--validation")
	anon := invoke("anonymous", "enable", "--config", path)
	if got := invoke("anonymous", "enable", "--config", path, "--mode", "required"); got != anon {
		t.Fatal("anonymous activation reset")
	}
	for _, mode := range []string{"off", "optional"} {
		var rejected, diagnostics bytes.Buffer
		if err := run([]string{"anonymous", "enable", "--config", path, "--mode", mode}, &rejected, &diagnostics); err == nil || rejected.Len() != 0 {
			t.Fatal("non-required Cookie mode accepted", mode)
		}
	}
	invoke("anonymous", "revoke-all", "--config", path)
	if got := invoke("anonymous", "enable", "--config", path, "--mode", "required"); got == anon {
		t.Fatal("generation did not advance")
	}
	invoke("check", "--config", path)

}
