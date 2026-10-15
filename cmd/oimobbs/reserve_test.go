// reserve CLIの既定読取り、必須引数、JSON出力、実適用を確認する。
package main

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/bootstrap"
	"os"
	"path/filepath"
	"testing"
)

func TestReserveCLI(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "data"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:8080", BaseURL: "http://127.0.0.1:8080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:8081", Origin: "http://127.0.0.1:8081", Transport: "loopback_tunnel"}, TrustedProxies: []string{}, CacheBytes: 268435456, EgressBits: 80000000}
	if _, e := bootstrap.Initialize(cfg, "reserve"); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(parent, "config.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"reserve"}, {"reserve", "unknown"}, {"reserve", "release", "--config", path}, {"reserve", "release", "--config", path, "--remaining-mib", "256"}, {"reserve", "status", "--config", path, "--apply"}} {
		var out, diag bytes.Buffer
		if e := run(args, &out, &diag); e == nil || out.Len() != 0 {
			t.Fatal(args, e, out.String())
		}
	}
	for _, step := range []struct {
		args           []string
		enabled, ready bool
		size           int64
	}{
		{[]string{"prepare"}, false, false, 0},
		{[]string{"prepare", "--apply"}, true, true, 256 << 20},
		{[]string{"release", "--remaining-mib", "0"}, true, true, 256 << 20},
		{[]string{"release", "--remaining-mib", "0", "--apply"}, true, false, 0},
		{[]string{"status"}, true, false, 0},
	} {
		var out, diag bytes.Buffer
		args := append([]string{"reserve"}, step.args...)
		args = append(args, "--config", path)
		if e := run(args, &out, &diag); e != nil {
			t.Fatal(args, e)
		}
		var s bootstrap.EmergencyReserveStatus
		if e := json.Unmarshal(out.Bytes(), &s); e != nil || s.Enabled != step.enabled || s.Ready != step.ready || s.Bytes != step.size {
			t.Fatal(s, e)
		}
	}
}
