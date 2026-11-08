// 自動分類の公開呼称を統一し、混在・不明回線に事業者別の掲示板風呼称を付ける。
package identity

var mixedProviderLabels = map[string]string{
	"ocn": "ｵｼﾏｾﾞ", "kddi": "ｱｳｱｳﾏｾﾞ", "softbank": "ﾔﾜﾗｶﾏｾﾞ",
	"iij": "ｲｲｼﾞｬﾝ", "optage": "ｵﾌﾟﾏｾﾞ", "biglobe": "ﾃﾞｶﾁｷｭｰ",
}

// AutomaticNetworkDisplay は分類・事業者キーを保持して自動表の旧表示を補正する。
// 手動上書きには適用せず、DNS特殊表示はこの補正より後で適用する。
func AutomaticNetworkDisplay(value NetworkClass) NetworkClass {
	switch value.Kind {
	case "fixed":
		value.Label, value.Suffix = DefaultNetworkDisplay(value.Kind)
	case "mixed":
		value.Label, value.Suffix = DefaultNetworkDisplay(value.Kind)
		if label, ok := mixedProviderLabels[value.Provider]; ok {
			value.Label = label
		}
	case "unknown":
		value.Label, value.Suffix = DefaultNetworkDisplay(value.Kind)
		if label, ok := unknownProviderLabels[value.Provider]; ok {
			value.Label = label
		} else if label, ok := mixedProviderLabels[value.Provider]; ok {
			value.Label = label
		}
	}
	return value
}
