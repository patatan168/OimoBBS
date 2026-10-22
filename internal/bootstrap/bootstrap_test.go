// 初期化の耐久境界と、検査時の非破壊性・所有排他を検証する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oimobbs/internal/platform"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	raw := `{"schema_version":1,"edge":null,"maintenance":null,"auto_reports":null,"data_dir":"data","public":{"listen":"127.0.0.1:9080","base_url":"http://127.0.0.1:9080","tls_cert_file":"","tls_key_file":""},"admin":{"listen":"127.0.0.1:9081","transport":"loopback_tunnel","origin":"http://127.0.0.1:9081"},"trusted_proxies":[],"egress_budget_bits_per_second":80000000}`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
func TestInitializeAndCheck(t *testing.T) {
	cfg := testConfig(t)
	first, err := Initialize(cfg, "永続サイト")
	if err != nil {
		t.Fatal(err)
	}
	again, err := Check(cfg)
	if err != nil || again.SiteID != first.SiteID || again.SiteName != "永続サイト" || again.SiteSeq != 1 || again.KeyCount != 10 {
		t.Fatalf("check: %+v %v", again, err)
	}
	master, err := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "master-000001.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Initialize(cfg, "上書き禁止"); err == nil {
		t.Fatal("reinitialization accepted")
	}
	after, err := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "master-000001.key"))
	if err != nil || !bytes.Equal(master, after) {
		t.Fatal("key overwritten")
	}
	lock, err := platform.Lock(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Check(cfg); err == nil {
		t.Fatal("second owner accepted")
	}
	if err = platform.Unlock(lock); err != nil {
		t.Fatal(err)
	}
	if _, err = Check(cfg); err != nil {
		t.Fatal("lock leaked", err)
	}
}
func TestCheckRejectsStorageDamage(t *testing.T) {
	for _, tc := range []string{"master_changed", "seed_changed", "missing_key", "permissions", "symlink", "partial_wal", "crc", "incomplete_init", "base_url", "unknown_marker", "owner_mismatch", "unexpected_data"} {
		t.Run(tc, func(t *testing.T) {
			cfg := testConfig(t)
			if _, err := Initialize(cfg, "試験"); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(cfg.DataDir, "keys", "master-000001.key")
			wal := filepath.Join(cfg.DataDir, "site", "control-000001.wal")
			switch tc {
			case "master_changed":
				mustWrite(t, key, bytes.Repeat([]byte{42}, 32))
			case "seed_changed":
				mustWrite(t, filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), bytes.Repeat([]byte{42}, 32))
			case "missing_key":
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(key, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				b, _ := os.ReadFile(key)
				target := filepath.Join(t.TempDir(), "key")
				mustWrite(t, target, b)
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, key); err != nil {
					t.Fatal(err)
				}
			case "partial_wal":
				b, _ := os.ReadFile(wal)
				mustWrite(t, wal, append(b, 1, 2, 3))
			case "crc":
				b, _ := os.ReadFile(wal)
				b[len(b)-12] ^= 1
				mustWrite(t, wal, b)
			case "incomplete_init":
				if err := os.Remove(filepath.Join(cfg.DataDir, "instance.json")); err != nil {
					t.Fatal(err)
				}
			case "base_url":
				cfg.Public.BaseURL = "http://127.0.0.1:9999"
			case "unknown_marker":
				path := filepath.Join(cfg.DataDir, "instance.json")
				b, _ := os.ReadFile(path)
				var v map[string]any
				_ = json.Unmarshal(b, &v)
				v["schema"] = 99
				b, _ = json.Marshal(v)
				mustWrite(t, path, b)
			case "owner_mismatch":
				path := filepath.Join(cfg.DataDir, "instance.json")
				b, _ := os.ReadFile(path)
				var v map[string]any
				_ = json.Unmarshal(b, &v)
				v["site_id"] = strings.Repeat("a", 32)
				b, _ = json.Marshal(v)
				mustWrite(t, path, b)
			case "unexpected_data":
				mustWrite(t, filepath.Join(cfg.DataDir, "boards", "orphan"), []byte("unverified"))
			}
			before, _ := os.ReadFile(wal)
			if _, err := Check(cfg); err == nil {
				t.Fatal("damaged storage accepted")
			}
			after, _ := os.ReadFile(wal)
			if !bytes.Equal(before, after) {
				t.Fatal("check rewrote WAL")
			}
		})
	}
}
func TestConfigRejections(t *testing.T) {
	cfg := testConfig(t)
	b, _ := json.Marshal(cfg)
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"schema", func(v map[string]any) { v["schema_version"] = 2 }},
		{"unknown", func(v map[string]any) { v["typo"] = 1 }},
		{"removed_cache_limit", func(v map[string]any) { v["cache_bytes"] = 0 }},
		{"missing", func(v map[string]any) { delete(v, "egress_budget_bits_per_second") }},
		{"fraction", func(v map[string]any) { v["egress_budget_bits_per_second"] = 1.5 }},
		{"external_http", func(v map[string]any) { v["public"].(map[string]any)["listen"] = "0.0.0.0:9080" }},
		{"external_admin", func(v map[string]any) { v["admin"].(map[string]any)["listen"] = "0.0.0.0:9081" }},
		{"same_origin", func(v map[string]any) { v["admin"].(map[string]any)["origin"] = cfg.Public.BaseURL }},
		{"same_port", func(v map[string]any) { v["admin"].(map[string]any)["listen"] = cfg.Public.Listen }},
		{"url_path", func(v map[string]any) { v["public"].(map[string]any)["base_url"] = cfg.Public.BaseURL + "/path" }},
		{"proxy_unimplemented", func(v map[string]any) { v["trusted_proxies"] = []string{"127.0.0.1/32"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v map[string]any
			_ = json.Unmarshal(b, &v)
			tc.edit(v)
			bad, _ := json.Marshal(v)
			path := filepath.Join(t.TempDir(), "bad.json")
			mustWrite(t, path, bad)
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("bad configuration accepted")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "duplicate.json")
	mustWrite(t, path, append([]byte(`{"schema_version":1,`), b[1:]...))
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("duplicate key accepted")
	}
}
func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
