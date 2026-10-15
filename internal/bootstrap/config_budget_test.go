// 起動設定が有限の帯域予算を受け付け、送信制御と同じ最大値を使うことを検査する。
package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/delivery"
)

func TestConfigEgressBudgets(t *testing.T) {
	cfg := testConfig(t)
	for _, bits := range []uint64{1, 80_000_000, delivery.MaxBudgetBits} {
		cfg.EgressBits = bits
		if err := cfg.validate(); err != nil {
			t.Fatal(bits, err)
		}
	}
	for _, bits := range []uint64{0, delivery.MaxBudgetBits + 1} {
		cfg.EgressBits = bits
		if err := cfg.validate(); err == nil {
			t.Fatal("invalid budget accepted", bits)
		}
	}
}

// 設定省略だけは80Mbpsへ補い、明示値と不正な値を区別する。
func TestLoadConfigEgressRequiredAndOverride(t *testing.T) {
	cfg := testConfig(t)
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, raw string
		want      uint64
		invalid   bool
	}{
		{"omitted", "", 0, true},
		{"lower", "40000000", 40_000_000, false},
		{"explicit_default", "80000000", 80_000_000, false},
		{"expanded", "240000000", 240_000_000, false},
		{"maximum", "1000000000", 1_000_000_000, false},
		{"zero", "0", 0, true},
		{"too_large", "1000000001", 0, true},
		{"null", "null", 0, true},
		{"negative", "-1", 0, true},
		{"string", `"80000000"`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if tc.raw == "" {
				delete(fields, "egress_budget_bits_per_second")
			} else {
				fields["egress_budget_bits_per_second"] = json.RawMessage(tc.raw)
			}
			body, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(path)
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid value accepted")
				}
				return
			}
			if err != nil || loaded.EgressBits != tc.want {
				t.Fatalf("budget=%d want=%d err=%v", loaded.EgressBits, tc.want, err)
			}
		})
	}
}
