// 保存済み標準設定の呼称を補正し、独自取得元・カテゴリーと手動CIDR上書きを保持する。
package bootstrap

import "oimobbs/internal/identity"

// repairStandardNetworkDisplays は複製済みの設定だけを更新し、回線区分や更新予定を変えない。
func repairStandardNetworkDisplays(config *NetworkConfig) {
	sources := map[uint32]bool{}
	categories := map[string]bool{}
	for _, preset := range networkSourcePresets {
		sources[preset.ASN] = true
		categories[presetProvider(preset.ID)] = true
	}
	for i, row := range config.Sources {
		if row.Type == "asn" && sources[row.ASN] {
			value := identity.AutomaticNetworkDisplay(identity.NetworkClass{Kind: row.Kind, Label: row.Label, Suffix: row.Suffix, Provider: row.Provider})
			config.Sources[i].Label, config.Sources[i].Suffix = value.Label, value.Suffix
		}
	}
	for _, category := range defaultNetworkCategories() {
		categories[category.ID] = true
	}
	for i, row := range config.Categories {
		if categories[row.ID] {
			value := identity.AutomaticNetworkDisplay(identity.NetworkClass{Kind: row.Kind, Label: row.Label, Suffix: row.Suffix, Provider: row.Provider})
			config.Categories[i].Label, config.Categories[i].Suffix = value.Label, value.Suffix
		}
	}
}
