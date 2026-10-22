// 固定・携帯混在を含む保存状態を識別し、対応前のreaderによる読み込みを防ぐ。
package bootstrap

import (
	"oimobbs/internal/identity"
	"slices"
)

const mixedNetworkReader uint32 = 85

// mixedNetworkRows は個々の接続方式を確定できない混在分類を含むか返す。
func mixedNetworkRows(rows []identity.NetworkClass) bool {
	for _, row := range rows {
		if row.Kind == "mixed" {
			return true
		}
	}
	return false
}

// mixedNetworkAccess は混在回線を独立して拒否する保存設定を識別する。
func mixedNetworkAccess(access *NetworkAccessSettings) bool {
	return access != nil && slices.Contains(access.DeniedKinds, "mixed")
}

// networkRequiresMixedReader は取得元・カテゴリー・上書き・取得済み表の混在分類を検出する。
func networkRequiresMixedReader(state networkState) bool {
	if mixedNetworkRows(state.Rows) || mixedNetworkRows(state.Config.Overrides) {
		return true
	}
	for _, source := range state.Config.Sources {
		if source.Kind == "mixed" {
			return true
		}
	}
	for _, category := range state.Config.Categories {
		if category.Kind == "mixed" {
			return true
		}
	}
	return false
}

// mixedNetworkRule は混在分類だけを対象とする条件規制を識別する。
func mixedNetworkRule(conditions []denialCondition) bool {
	for _, condition := range conditions {
		if condition.Field == "line" && condition.Value == "mixed" {
			return true
		}
	}
	return false
}
