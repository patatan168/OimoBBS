// 通報板を持たない起動設定と、管理画面での通報有効状態の表示を検証する。
package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/postcapture"
)

func TestLoadConfigAutoReportsWithoutBoard(t *testing.T) {
	cfg := testConfig(t)
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, reports string
		valid         bool
	}{
		{"enabled", `{"since":"2026-01-01T00:00:00Z"}`, true},
		{"disabled", `null`, true},
		{"legacy_board", `{"board_key":"missing","since":"2026-01-01T00:00:00Z"}`, true},
		{"invalid_legacy_board", `{"board_key":"../report","since":"2026-01-01T00:00:00Z"}`, false},
		{"null_legacy_board", `{"board_key":null,"since":"2026-01-01T00:00:00Z"}`, false},
		{"duplicate_legacy_board", `{"board_key":"report","board_key":"other","since":"2026-01-01T00:00:00Z"}`, false},
		{"unknown_field", `{"target_board":"report","since":"2026-01-01T00:00:00Z"}`, false},
		{"missing_since", `{}`, false},
		{"duplicate_since", `{"since":"2026-01-01T00:00:00Z","since":"2026-01-02T00:00:00Z"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			fields["auto_reports"] = json.RawMessage(tc.reports)
			raw, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
			if tc.valid && (loaded.AutoReports != nil) != (tc.name != "disabled") {
				t.Fatal("unexpected activation state")
			}
			if tc.valid && loaded.AutoReports != nil {
				current, err := json.Marshal(loaded.AutoReports)
				if err != nil || strings.Contains(string(current), "board_key") {
					t.Fatal("legacy board setting retained", err)
				}
			}
		})
	}
}

func TestOperationsAutoReportsWithoutBoard(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			cfg, repo := adminFixture(t)
			repo.Close()
			if enabled {
				cfg.AutoReports = &AutoReportConfig{Since: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}
			}
			repo, err := OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal(err)
			}
			defer repo.Close()
			if len(repo.posting) != 0 {
				t.Fatal("fixture unexpectedly has a board")
			}
			client := newAdminClient(t, repo)
			defer client.server.Close()
			if client.login(adminTestSecret) != 303 {
				t.Fatal("login")
			}
			res, body := client.request("GET", "/operations", "", nil)
			if res.StatusCode != 200 || strings.Contains(body, "自動通報は有効です") != enabled || strings.Contains(body, "自動通報は起動設定で無効") == enabled {
				t.Fatal("incorrect activation state", res.StatusCode)
			}
			res, body = client.request("GET", "/api/v1/operations", "", nil)
			if res.StatusCode != 200 || strings.Contains(body, "report_board") {
				t.Fatal("obsolete board setting exposed", res.StatusCode)
			}
		})
	}
}
