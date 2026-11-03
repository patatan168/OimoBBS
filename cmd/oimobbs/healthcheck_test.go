// CLI監視が公開入口からトップページと保存状態の両方を確認することを実TLSで検査する。
package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestHealthcheckRequiresStorageReadiness(t *testing.T) {
	for _, tc := range []struct {
		name            string
		root, readiness int
		body            string
		healthy         bool
	}{
		{"ready", 200, 200, "ok\n", true},
		{"storage-stopped", 200, 503, "unavailable\n", false},
		{"missing-route", 200, 404, "missing\n", false},
		{"generic-success", 200, 200, "site page\n", false},
		{"empty-success", 200, 200, "", false},
		{"unavailable-home", 503, 200, "ok\n", false},
		{"redirect", 200, 302, "ok\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, _ := publicFixture(t)
			pair, err := tls.LoadX509KeyPair(cfg.Public.TLSCert, cfg.Public.TLSKey)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var paths []string
			front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				if r.Header.Get("Accept-Encoding") != "gzip" {
					w.WriteHeader(406)
					return
				}
				if r.URL.Path == "/" {
					w.WriteHeader(tc.root)
					io.WriteString(w, "home\n")
					return
				}
				if r.URL.Path != "/.well-known/oimobbs-health" {
					w.WriteHeader(404)
					return
				}
				w.Header().Set("Location", "/")
				w.WriteHeader(tc.readiness)
				io.WriteString(w, tc.body)
			}))
			front.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
			front.StartTLS()
			defer front.Close()
			cfg.Public.BaseURL = front.URL
			origin, _ := url.Parse(front.URL)
			cfg.Public.Listen = origin.Host
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(config, raw, 0600); err != nil {
				t.Fatal(err)
			}
			err = runHealthcheck([]string{"--config", config}, io.Discard)
			if (err == nil) != tc.healthy {
				t.Fatal("healthcheck outcome", err, tc.healthy)
			}
			mu.Lock()
			defer mu.Unlock()
			wantCalls := 2
			if tc.root != 200 {
				wantCalls = 1
			}
			if len(paths) != wantCalls || paths[0] != "/" {
				t.Fatal("public route checks", paths)
			}
		})
	}
}
