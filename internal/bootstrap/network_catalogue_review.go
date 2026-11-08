// 公開された接続サービスに基づく標準分類と、更新時に対象ASNを上書きする処理を管理する。
package bootstrap

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"reflect"
	"strings"
)

// reviewedNetworkKinds は2026-11-05の見直し対象。根拠と推定の限界はdocs/testing/network-catalogue-review.mdを参照。
// ISPという登録だけでは変更せず、接続サービスを確認できた事業者だけを対象にする。
var reviewedNetworkKinds = map[uint32]string{
	2497: "mixed", 2518: "mixed",
	9351: "fixed", 9365: "fixed", 10001: "fixed", 17529: "fixed", 17530: "fixed",
	17682: "fixed", 17698: "fixed", 18092: "fixed", 18129: "fixed", 18135: "fixed",
	18281: "fixed", 23780: "fixed", 23827: "fixed", 24255: "fixed", 24289: "fixed",
	24290: "fixed", 55376: "fixed", 55391: "fixed", 55392: "fixed", 59108: "fixed",
	59125: "fixed", 59126: "fixed", 131916: "fixed", 131943: "fixed", 131982: "fixed",
	59104: "academic",
}

// prepareNetworkCatalogueRefresh は自動・手動取得の直前に標準分類を耐久保存する。
// falseは管理設定が先に変更されたための中止。成功時だけ呼出元の取得状態を更新する。
func (r *Repository) prepareNetworkCatalogueRefresh(snapshot *store.ControlState, state *networkState) (bool, error) {
	config := reclassifyStandardNetworks(state.Config)
	if reflect.DeepEqual(config, state.Config) {
		return true, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return false, err
	}
	if r.site.State().Rows["network:active"].Revision != snapshot.Rows["network:active"].Revision {
		return false, nil
	}
	if state.Version == ^domain.U64(0) {
		return false, store.ErrCorrupt
	}
	next := *state
	next.Config = config
	next.Version++
	if err := r.publishNetworks(next, nil, "network_config", nil); err != nil {
		return false, err
	}
	*snapshot, *state = r.site.State(), next
	return true, nil
}

// reviewedNetworkPresets は確認済みの用途を反映し、自動分類の呼称を統一する。
func reviewedNetworkPresets(previous []networkPreset) []networkPreset {
	rows := append([]networkPreset(nil), previous...)
	for i := range rows {
		kind, ok := reviewedNetworkKinds[rows[i].ASN]
		if !ok {
			continue
		}
		rows[i].Kind = kind
		description := "固定/MVNO混在"
		if kind != "mixed" {
			rows[i].Label, rows[i].Suffix = identity.DefaultNetworkDisplay(kind)
			description = "固定推定"
			if kind == "academic" {
				description = "学術網"
			}
		}
		rows[i].Name = strings.NewReplacer("用途混在/未確定", description, "用途混在", description).Replace(rows[i].Name)
	}
	for i, row := range rows {
		value := identity.AutomaticNetworkDisplay(identity.NetworkClass{Kind: row.Kind, Label: row.Label, Suffix: row.Suffix, Provider: presetProvider(row.ID)})
		rows[i].Label, rows[i].Suffix = value.Label, value.Suffix
	}
	return rows
}

// networkPresetSource は標準値を管理画面で保存する取得元へ変換する。
func networkPresetSource(p networkPreset) NetworkSource {
	return NetworkSource{Name: p.Name, Type: "asn", ASN: p.ASN, Kind: p.Kind, Label: p.Label, Suffix: p.Suffix, Provider: presetProvider(p.ID)}
}

// networkPresetCategory はASN事業者の汎用カテゴリーを組み立てる。サービス固有カテゴリーとは分ける。
func networkPresetCategory(p networkPreset) NetworkCategory {
	provider := presetProvider(p.ID)
	name, _, _ := strings.Cut(p.Name, "（AS")
	return NetworkCategory{ID: provider, Provider: provider, Name: name, Kind: p.Kind, Label: p.Label, Suffix: p.Suffix, Description: "事業者のASNから取得する推定です。共有する上流回線やIPoEでは契約サービスまで区別できない場合があります。"}
}

// reclassifyStandardNetworks は対象ASNの取得元と標準事業者カテゴリーを見直し後の値で上書きする。
// 取得済み表は次の取得成功まで保持し、手動のIP上書き・停止状態・更新間隔を維持する。
func reclassifyStandardNetworks(config NetworkConfig) NetworkConfig {
	config.Sources = append([]NetworkSource{}, config.Sources...)
	config.Categories = append([]NetworkCategory{}, config.Categories...)
	sources, categories := reviewedNetworkReplacements()
	for i, source := range config.Sources {
		if updated, ok := sources[source.ASN]; source.Type == "asn" && ok {
			config.Sources[i] = updated
		}
	}
	for i, category := range config.Categories {
		if updated, ok := categories[category.ID]; ok {
			config.Categories[i] = updated
		}
	}
	repairStandardNetworkDisplays(&config)
	return config
}

// reviewedNetworkReplacements は見直し対象の取得元と汎用の事業者カテゴリーを索引化する。
// サービス固有のカテゴリーへ、ASN全体の推定を適用しない。
func reviewedNetworkReplacements() (map[uint32]NetworkSource, map[string]NetworkCategory) {
	sources := map[uint32]NetworkSource{}
	categories := map[string]NetworkCategory{}
	providers := map[string]bool{}
	for _, source := range defaultNetworkSources() {
		if _, ok := reviewedNetworkKinds[source.ASN]; source.Type == "asn" && ok {
			sources[source.ASN] = source
			providers[source.Provider] = true
		}
	}
	for _, category := range defaultNetworkCategories() {
		if providers[category.ID] {
			categories[category.ID] = category
		}
	}
	return sources, categories
}
