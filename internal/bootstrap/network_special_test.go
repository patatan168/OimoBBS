// 特殊分類の表示・独立した規制・耐久保存・旧reader拒否とクラウド複数起源の順序独立性を検証する。
package bootstrap

import (
	"encoding/json"
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
	"testing"
)

func TestSpecialNetworkDisplayPermissionsAndReaders(t *testing.T) {
	for _, tc := range []struct{ kind, label, suffix string }{{"academic", "ｶﾞｯｸｼ", "6"}, {"school", "ﾎﾞﾝﾎﾞﾝ", "7"}, {"government", "ｺﾑｲｰﾝ", "G"}, {"business", "ｼｬﾁｰｸ", "C"}, {"hosting", "ｸﾓﾉｳｴ", "V"}, {"satellite", "ｳﾁｭｰ", "U"}} {
		t.Run(tc.kind, func(t *testing.T) {
			label, suffix := identity.DefaultNetworkDisplay(tc.kind)
			if label != tc.label || suffix != tc.suffix {
				t.Fatal(label, suffix)
			}
			row := identity.NetworkClass{CIDR: "192.0.2.0/24", Kind: tc.kind, Label: label, Suffix: suffix}
			table, err := identity.CompileNetworks([]identity.NetworkClass{row}, 1)
			if err != nil {
				t.Fatal(err)
			}
			c := &identity.NetworkClassifier{Automatic: table}
			ip := netip.MustParseAddr("192.0.2.1")
			for _, denied := range []string{tc.kind, "unknown", "fixed"} {
				p := &NetworkAccessSettings{AllowVPN: true, DeniedKinds: []string{denied}}
				if p.validate() != nil {
					t.Fatal("invalid policy")
				}
				if (checkNetworkPermission(c, p, ip) == ErrNetworkPermission) != (denied == tc.kind) {
					t.Fatal("wrong denial", denied)
				}
			}
			policy := defaultReadingPolicy()
			policy.Network.DeniedKinds = []string{tc.kind}
			raw, _ := json.Marshal(policy)
			if readingMinimumReader(raw) != 92 {
				t.Fatal("reading reader")
			}
			b := boardValue{Settings: defaultBoardSettings()}
			b.Settings.Identity.Networks = []identity.NetworkClass{row}
			if validateIdentityReader(siteState{MinimumReader: 91}, b) != store.ErrCorrupt {
				t.Fatal("old board reader")
			}
			if !specialNetworkRule([]denialCondition{{Field: "line", Value: tc.kind}}) {
				t.Fatal("rule reader")
			}
		})
	}
}

func TestSpecialNetworkPersistenceAndOldReader(t *testing.T) {
	cfg, r := adminFixture(t)
	state, err := loadNetworkState(r.site.State())
	if err != nil {
		t.Fatal(err)
	}
	state.Version = 1
	state.Config.Overrides = []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "hosting", Label: "ｸﾓﾉｳｴ", Suffix: "V"}}
	r.mu.Lock()
	err = r.publishNetworks(state, nil, "special_test", nil)
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var site siteState
	snapshot := r.site.State()
	if strictjson.Decode(snapshot.Rows["site:state"].Value, &site) != nil || site.MinimumReader != 92 {
		t.Fatal(site)
	}
	site.MinimumReader = 91
	row := snapshot.Rows["site:state"]
	row.Value, _ = json.Marshal(site)
	snapshot.Rows["site:state"] = row
	if _, err = inspectSiteState(snapshot, site.ID, cfg.Public.BaseURL); err == nil {
		t.Fatal("old site reader accepted special classification")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := r.liveNetworks.Load().Classify(nil, netip.MustParseAddr("192.0.2.1")); got.Label != "ｸﾓﾉｳｴ" || got.Suffix != "V" {
		t.Fatal(got)
	}
	r.mu.Lock()
	err = r.enableDenials(domain.NewID(), true, false, false, false, true, false, false, false, true)
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostingMultipleOriginsAreOrderIndependent(t *testing.T) {
	a := identity.NetworkClass{CIDR: "192.0.2.0/24", Kind: "hosting", Label: "ｸﾓﾉｳｴ", Suffix: "V", Provider: "aws"}
	b := a
	b.Provider = "vultr"
	for _, rows := range [][]identity.NetworkClass{{a, b, a}, {b, a, b}} {
		seen := map[string]identity.NetworkClass{}
		all := []identity.NetworkClass{}
		for _, row := range rows {
			batch, err := retainNetworkBatch([]identity.NetworkClass{row}, seen)
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, batch...)
		}
		if seen[a.CIDR].Provider != "" || len(all) != 2 {
			t.Fatal(seen, all)
		}
	}
	for _, change := range []string{"kind", "label", "suffix"} {
		bad := b
		switch change {
		case "kind":
			bad.Kind = "vpn"
		case "label":
			bad.Label = "other"
		case "suffix":
			bad.Suffix = "8"
		}
		if _, ok := mergeHostingNetwork(a, bad); ok {
			t.Fatal("unsafe collision", change)
		}
	}
	if slices.Contains([]string{"C", "U", "0"}, a.Suffix) {
		t.Fatal("cloud suffix collision")
	}
}
