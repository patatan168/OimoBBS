// 標準呼称の網羅検査と、保存済みの事業者名を投稿表示から除く更新境界を検証する。
package bootstrap

import (
	"oimobbs/internal/identity"
	"reflect"
	"testing"
	"unicode/utf8"
)

// TestStandardNetworkDisplays は取得元・カテゴリー・DNS補完の全表示を許可済みの呼称と照合する。
func TestStandardNetworkDisplays(t *testing.T) {
	allowed := map[string]map[string]bool{}
	add := func(kind, label, suffix string) {
		if allowed[kind] == nil {
			allowed[kind] = map[string]bool{}
		}
		allowed[kind][label+"/"+suffix] = true
	}
	for _, preset := range networkDisplayPresets {
		add(preset.Kind, preset.Label, preset.Suffix)
	}
	add("unknown", "ﾜｶﾗﾝ", "0")
	for _, label := range []string{"ｵｼﾏｾﾞ", "ｱｳｱｳﾏｾﾞ", "ﾔﾜﾗｶﾏｾﾞ", "ｲｲｼﾞｬﾝ", "ｵﾌﾟﾏｾﾞ", "ﾃﾞｶﾁｷｭｰ"} {
		add("mixed", label, "0")
	}
	providerLabels := map[string]string{}
	check := func(name, kind, label, suffix, provider string) {
		t.Helper()
		if kind == "unknown" && provider != "" {
			if label == "ﾜｶﾗﾝ" || suffix != "0" || utf8.RuneCountInString(label) > 16 || label == "" {
				t.Errorf("%s: missing provider display %s/%s", name, label, suffix)
			}
			for _, r := range label {
				if r < 'ｦ' || r > 'ﾟ' {
					t.Errorf("%s: provider display is not half-width katakana: %s", name, label)
				}
			}
			if previous, exists := providerLabels[provider]; exists && previous != label {
				t.Errorf("%s: provider has inconsistent displays: %s / %s", provider, previous, label)
			}
			providerLabels[provider] = label
			return
		}
		if !allowed[kind][label+"/"+suffix] {
			t.Errorf("%s: unexpected %s display %s/%s", name, kind, label, suffix)
		}
	}
	for _, preset := range networkSourcePresets {
		check(preset.ID, preset.Kind, preset.Label, preset.Suffix, presetProvider(preset.ID))
	}
	if len(providerLabels) != 79 {
		t.Fatal("unknown provider coverage", len(providerLabels))
	}
	seenLabels := map[string]string{}
	for provider, label := range providerLabels {
		if previous, exists := seenLabels[label]; exists && previous != provider {
			t.Errorf("providers share a display: %s / %s = %s", previous, provider, label)
		}
		seenLabels[label] = provider
	}
	for _, category := range defaultNetworkCategories() {
		check(category.ID, category.Kind, category.Label, category.Suffix, category.Provider)
	}
	for _, rule := range identity.ServiceHostRules() {
		check(rule.Pattern, rule.Kind, rule.Label, rule.Suffix, rule.Provider)
	}
}

// TestStandardNetworkDisplayRefresh は分類の追加変更をせず、標準の旧呼称だけを修正する。
func TestStandardNetworkDisplayRefresh(t *testing.T) {
	config := defaultNetworkConfig()
	config.Sources = defaultNetworkSources()
	config.Categories = defaultNetworkCategories()
	for i := range config.Sources {
		switch config.Sources[i].Kind {
		case "fixed", "mixed", "unknown":
			config.Sources[i].Label = "OLD"
		}
	}
	for i := range config.Categories {
		switch config.Categories[i].Kind {
		case "fixed", "mixed", "unknown":
			config.Categories[i].Label = "OLD"
		}
	}
	custom := NetworkSource{Name: "独自取得元", Type: "asn", ASN: 64512, Kind: "unknown", Label: "独自", Suffix: "0", Provider: "custom"}
	category := NetworkCategory{ID: "custom-display", Name: "独自表示", Kind: "unknown", Label: "独自", Suffix: "0"}
	config.Sources = append(config.Sources, custom)
	config.Categories = append(config.Categories, category)
	config.Overrides = []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "mixed", Label: "手動保持", Suffix: "0"}}
	want := defaultNetworkConfig()
	want.Sources = append(defaultNetworkSources(), custom)
	want.Categories = append(defaultNetworkCategories(), category)
	want.Overrides = config.Overrides
	snapshot := append([]NetworkSource(nil), config.Sources...)
	got := reclassifyStandardNetworks(config)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("standard displays not repaired or other settings changed")
	}
	if !reflect.DeepEqual(config.Sources, snapshot) || !reflect.DeepEqual(got, reclassifyStandardNetworks(got)) {
		t.Fatal("input mutated or refresh not idempotent")
	}
}
