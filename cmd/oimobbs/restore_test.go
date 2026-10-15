// CLI復元の成功JSONと既存先/不足引数の非変更拒否を検査する。
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"oimobbs/internal/bootstrap"
)

func TestRestoreCLI(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "source"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:9080", BaseURL: "http://127.0.0.1:9080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:9081", Transport: "loopback_tunnel", Origin: "http://127.0.0.1:9081"}, TrustedProxies: []string{}, CacheBytes: 268435456, EgressBits: 80000000}
	sourceFile, targetFile := filepath.Join(parent, "source.json"), filepath.Join(parent, "target.json")
	raw, _ := json.Marshal(cfg)
	if e := os.WriteFile(sourceFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := bootstrap.Initialize(cfg, "CLI復元"); e != nil {
		t.Fatal(e)
	}
	cfg.DataDir = filepath.Join(parent, "restored")
	raw, _ = json.Marshal(cfg)
	if e := os.WriteFile(targetFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	args := []string{"restore", "--source-config", sourceFile, "--config", targetFile}
	var output, diagnostics bytes.Buffer
	if e := run(args, &output, &diagnostics); e != nil {
		t.Fatal(e, diagnostics.String())
	}
	var report bootstrap.PublicRestoreReport
	if e := json.Unmarshal(output.Bytes(), &report); e != nil || !report.RestoreReady {
		t.Fatal(output.String(), e)
	}
	if _, e := bootstrap.Check(cfg); e != nil {
		t.Fatal(e)
	}
	for _, invalid := range [][]string{args, {"restore", "--config", targetFile}, {"restore", "--source-config", sourceFile, "--config", targetFile, "extra"}} {
		output.Reset()
		if e := run(invalid, &output, &diagnostics); e == nil || output.Len() != 0 {
			t.Fatal("failure emitted restore ready", e, output.String())
		}
	}
}

func TestEdgeHealthcheckUsesPublicOrigin(t *testing.T) {
	cfg, _, _ := publicFixture(t)
	pair, e := tls.LoadX509KeyPair(cfg.Public.TLSCert, cfg.Public.TLSKey)
	if e != nil {
		t.Fatal(e)
	}
	var served atomic.Bool
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served.Store(true); w.WriteHeader(200) }))
	front.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	front.StartTLS()
	defer front.Close()
	cfg.Public.BaseURL = front.URL
	cfg.TrustedProxies = []string{"127.0.0.1/32"}
	cfg.Edge = &bootstrap.EdgeConfig{ID: "edge", Revision: 1, ClientCA: cfg.Public.TLSCert, CertificateSHA256: strings.Repeat("0", 64)}
	raw, _ := json.Marshal(cfg)
	configFile := filepath.Join(t.TempDir(), "edge.json")
	if e = os.WriteFile(configFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var diagnostics bytes.Buffer
	if e = runHealthcheck([]string{"--config", configFile}, &diagnostics); e != nil || !served.Load() {
		t.Fatal(e, diagnostics.String())
	}
}

// TestRestoreCLIWithBackup は旧候補の認証と最新側の制御を使うCLI入口を検査する。
func TestRestoreCLIWithBackup(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "latest"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:9080", BaseURL: "http://127.0.0.1:9080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:9081", Transport: "loopback_tunnel", Origin: "http://127.0.0.1:9081"}, TrustedProxies: []string{}, CacheBytes: 268435456, EgressBits: 80000000}
	if _, e := bootstrap.Initialize(cfg, "合成復元CLI"); e != nil {
		t.Fatal(e)
	}
	backup := filepath.Join(parent, "old-backup")
	if _, e := bootstrap.CaptureOfflineBackup(t.Context(), cfg, backup); e != nil {
		t.Fatal(e)
	}
	sourceFile, targetFile := filepath.Join(parent, "latest.json"), filepath.Join(parent, "restored.json")
	raw, _ := json.Marshal(cfg)
	if e := os.WriteFile(sourceFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	cfg.DataDir = filepath.Join(parent, "restored")
	raw, _ = json.Marshal(cfg)
	if e := os.WriteFile(targetFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var out, diagnostics bytes.Buffer
	if e := run([]string{"restore", "--source-config", sourceFile, "--backup", backup, "--config", targetFile}, &out, &diagnostics); e != nil {
		t.Fatal(e, diagnostics.String())
	}
	var report bootstrap.PublicRestoreReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil || !report.RestoreReady || report.Backup == nil {
		t.Fatal(out.String(), e)
	}
	if _, e := bootstrap.Check(cfg); e != nil {
		t.Fatal(e)
	}
}
