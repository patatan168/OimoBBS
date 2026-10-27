// 現行の完全保存JSONと、旧サイト・省略型・旧投稿スキーマの拒否を検査する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentStorageRejectsOldSiteWithoutMutation(t *testing.T) {
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "現行形式"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.DataDir, "instance.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var marker instance
	if err = strictjson.Decode(raw, &marker); err != nil || marker.Schema != storageFormatVersion {
		t.Fatal(marker, err)
	}
	for _, schema := range []uint32{1, 2, 3, 4} {
		marker.Schema = schema
		old, _ := json.Marshal(marker)
		if err = os.WriteFile(path, old, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = Check(cfg); err == nil {
			t.Fatal("old site accepted by check", schema)
		}
		if repo, err := OpenPostingRepository(cfg, postcapture.Validate); err == nil {
			repo.Close()
			t.Fatal("old site opened", schema)
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(old) {
			t.Fatal("old instance was migrated", schema)
		}
	}
}

func TestCurrentStorageRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name   string
		value  any
		field  string
		target any
	}{
		{"board", defaultBoardSettings().Identity, "networks", &boardIdentity{}},
		{"access", NetworkAccessSettings{AllowVPN: true}, "denied_countries", &NetworkAccessSettings{}},
		{"network", defaultNetworkConfig(), "access_overrides", &NetworkConfig{}},
		{"class", identity.NetworkClass{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0", Provider: "ocn"}, "provider", &identity.NetworkClass{}},
		{"category", defaultNetworkCategories()[0], "description", &NetworkCategory{}},
		{"rule", denialRule{ID: domain.NewID(), Scope: denialScope{Board: domain.NewID()}, Operations: []string{}, Conditions: []denialCondition{}}, "auto_report_refs", &denialRule{}},
		{"report", deletionReport{ID: domain.NewID(), Board: domain.NewID()}, "automatic", &deletionReport{ID: domain.NewID(), Board: domain.NewID()}},
		{"backup", backupManifest{ID: domain.NewID(), Site: domain.NewID(), ControlCut: []backupCut{}, Entries: []backupEntry{}, KeyIDs: []uint32{}}, "required_original_holds_omitted", &backupManifest{ID: domain.NewID(), Site: domain.NewID(), ControlCut: []backupCut{}, Entries: []backupEntry{}, KeyIDs: []uint32{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			// 完全型の解釈を先に確認し、項目削除だけで拒否が変わることを検査する。
			if err = strictjson.Decode(raw, tc.target); err != nil {
				t.Fatal("current", err)
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(raw, &fields)
			delete(fields, tc.field)
			old, _ := json.Marshal(fields)
			if err = strictjson.Decode(old, tc.target); err == nil {
				t.Fatal("incomplete old format accepted")
			}
		})
	}
	for _, schema := range []string{"form-post-v1", "form-post-v2", "form-post-v3", "form-post-v4", "form-post-v5", "form-post-v6", "form-post-v7", "http-observation-v1", "http-observation-v2", "http-observation-v3"} {
		raw, _ := json.Marshal(map[string]string{"schema": schema})
		if postcapture.Validate(raw) == nil {
			t.Fatal("old posting capture accepted", schema)
		}
	}
}

// 成立票・保存ポリシーのない旧自動停止を、現在設定や最後の一票で救済しない。
func TestCurrentAutomaticStopRequiresStoredPolicy(t *testing.T) {
	p := defaultReportPolicy()
	id := domain.NewID()
	r := denialRule{ID: id, Reason: "abuse", Effect: denialEffect{Type: "deny"}, Conditions: []denialCondition{{"token", "exact", domain.Hash{1}.String(), "deny"}}, Starts: 1, Expires: 1 + domain.Time(p.stop()), ReportPolicy: &p, Reports: []autoReportEvidenceRef{{domain.NewID(), autoReportReference{"news", 1, 1}}, {domain.NewID(), autoReportReference{"news", 1, 1}}, {id, autoReportReference{"news", 1, 1}}}}
	if err := validateAutoReportRefs(r); err != nil {
		t.Fatal(err)
	}
	r.ReportPolicy = nil
	if validateAutoReportRefs(r) == nil || ruleReportPolicy(r).valid() {
		t.Fatal("missing policy repaired")
	}
	r.Reports = nil
	if automaticStopRule(r) {
		t.Fatal("manual or old token rule classified as automatic")
	}
}
