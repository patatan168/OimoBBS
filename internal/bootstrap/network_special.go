// 学術・学校・官公庁・企業・ホスティング・衛星の保存状態とreader境界を共通化する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const specialNetworkReader uint32 = 92
const dnsDisplayReader uint32 = 93

// specialNetworkKind は接続方式と区別する特殊用途の分類を判定する。
func specialNetworkKind(kind string) bool { return identity.SpecialNetworkKind(kind) }

// specialNetworkRows は自動表と手動上書きの新分類を検出する。
func specialNetworkRows(rows []identity.NetworkClass) bool {
	for _, row := range rows {
		if specialNetworkKind(row.Kind) {
			return true
		}
	}
	return false
}

// specialNetworkAccess は新分類の拒否設定が旧readerで無視されることを防ぐ。
func specialNetworkAccess(access *NetworkAccessSettings) bool {
	if access == nil {
		return false
	}
	for _, kind := range access.DeniedKinds {
		if specialNetworkKind(kind) {
			return true
		}
	}
	return false
}

// networkRequiresSpecialReader は取得元・カテゴリー・取得済み表をまとめて検査する。
func networkRequiresSpecialReader(state networkState) bool {
	config, _ := json.Marshal(state.Config)
	if len(config) > 64<<10 {
		return true
	}
	raw, _ := json.Marshal([]identity.NetworkClass(state.Rows))
	if len(raw) > strictjson.MaxBytes-32 {
		return true
	}
	if specialNetworkRows(state.Rows) || specialNetworkRows(state.Config.Overrides) {
		return true
	}
	for _, source := range state.Config.Sources {
		if specialNetworkKind(source.Kind) {
			return true
		}
	}
	for _, category := range state.Config.Categories {
		if specialNetworkKind(category.Kind) {
			return true
		}
	}
	return false
}

// specialNetworkRule は新分類を使う投稿規制を検出する。
func specialNetworkRule(conditions []denialCondition) bool {
	for _, c := range conditions {
		if c.Field == "line" && specialNetworkKind(c.Value) {
			return true
		}
	}
	return false
}

// enableSpecialNetworkHosts は公開受付前にDNSによる特殊分類・h/H表示を扱うreader境界を耐久保存する。サイトmutex必須。
func (r *Repository) enableSpecialNetworkHosts() error {
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	if site.MinimumReader >= dnsDisplayReader {
		return nil
	}
	site.MinimumReader = dnsDisplayReader
	if err := appendControl(r.site, "network_special_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); err != nil {
		r.stopped = true
		return err
	}
	return nil
}
