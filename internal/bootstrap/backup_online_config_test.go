// 周期設定の旧形式省略・未知・重複キーを拒否する。
package bootstrap

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnlineBackupConfigCompleteFormat(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	c := OnlineBackupConfig{CopyParent: expiredSweepParent(t), KeysParent: expiredSweepParent(t), PartialPlanParent: expiredSweepParent(t), PartialKeysPlanParent: expiredSweepParent(t), KeysPlanParent: expiredSweepParent(t), PairPlanParent: expiredSweepParent(t), WorkParent: expiredSweepParent(t), ControlParent: expiredSweepParent(t), TrustInstance: onlineOutput(t, "config-trust.json"), IntervalSeconds: 3600, BudgetSeconds: 60}
	trust, e := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeNew(c.TrustInstance, trust); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(c)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	delete(fields, "reclaim")
	delete(fields, "cleanup_key")
	legacy, _ := json.Marshal(fields)
	cases := []struct {
		name           string
		raw            []byte
		valid, reclaim bool
	}{
		{"legacy_rejected", legacy, false, false},
		{"enabled", []byte(strings.Replace(string(raw), `"reclaim":false`, `"reclaim":true`, 1)), true, true},
		{"unknown", []byte(strings.TrimSuffix(string(legacy), "}") + `,"unknown":false}`), false, false},
		{"duplicate", []byte(strings.TrimSuffix(string(raw), "}") + `,"reclaim":true}`), false, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := onlineOutput(t, "config.json")
			if e = writeNew(path, test.raw); e != nil {
				t.Fatal(e)
			}
			loaded, e := LoadOnlineBackupConfig(path, cfg)
			if (e == nil) != test.valid {
				t.Fatal(loaded, e)
			}
			if test.valid {
				options, _ := loaded.Options()
				if options.Reclaim != test.reclaim {
					t.Fatal("reclaim default", options.Reclaim)
				}
			}
		})
	}
}
