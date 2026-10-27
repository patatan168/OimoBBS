// 板別の閲覧画面へ共通設定と変更できない条件を表示し、板固有の保存値を保持する。
package bootstrap

import (
	"slices"
	"strings"
)

type readingMasterRow struct{ Label, Value string }

// MasterValue は共通設定がONで固定される入力の表示値を返す。空なら板で編集できる。
func (p readingPage) MasterValue(name string) string {
	if p.Master == nil || !p.Master.Policy.Enabled {
		return ""
	}
	v := p.Master.Policy
	switch name {
	case "allow_local_ip":
		if v.AllowLocalIP != nil && !*v.AllowLocalIP {
			return "false"
		}
	case "allow_loopback_ip":
		if v.AllowLoopbackIP != nil && !*v.AllowLoopbackIP {
			return "false"
		}
	case "japan_only":
		if v.Network.JapanOnly {
			return "true"
		}
	case "allow_vpn":
		if !v.Network.AllowVPN {
			return "false"
		}
	case "deny_unresolved":
		if v.Network.denyUnresolvedHost() {
			return "true"
		}
	case "deny_crawlers":
		if v.DenyCrawlers {
			return "true"
		}
	default:
		if strings.HasPrefix(name, "allow_") && slices.Contains(v.Network.DeniedKinds, strings.TrimPrefix(name, "allow_")) {
			return "false"
		}
	}
	return ""
}

// DisplayValue は共通の固定値を表示し、保存する板固有の値と区別する。
func (p readingPage) DisplayValue(name string) string {
	if value := p.MasterValue(name); value != "" {
		return value
	}
	return p.Values.Get(name)
}

// MasterRows は共通設定の現在値を、ON/OFFにかかわらず確認できる一覧へ変換する。
func (p readingPage) MasterRows() []readingMasterRow {
	if p.Master == nil {
		return nil
	}
	v := p.Master.Policy
	denied := []string{}
	for _, kind := range p.Kinds {
		if slices.Contains(v.Network.DeniedKinds, kind.Value) {
			denied = append(denied, kind.Label)
		}
	}
	special := func(value *bool) string {
		if value == nil {
			return "回線・国・VPN条件に従う"
		}
		if *value {
			return "許可"
		}
		return "拒否"
	}
	list := func(values []string) string {
		if len(values) == 0 {
			return "指定なし"
		}
		return strings.Join(values, "\n")
	}
	country, vpn, reverse, crawler := "国外も許可", "許可", "許可", "追加制限なし"
	if v.Network.JapanOnly {
		country = "日本のみ許可"
	}
	if !v.Network.AllowVPN {
		vpn = "拒否"
	}
	if v.Network.denyUnresolvedHost() {
		reverse = "拒否"
	}
	if v.DenyCrawlers {
		crawler = "拒否"
	}
	return []readingMasterRow{{"ローカルIP", special(v.AllowLocalIP)}, {"サーバー自身", special(v.AllowLoopbackIP)}, {"拒否する回線種別", list(denied)}, {"登録国", country}, {"既知VPN", vpn}, {"逆引きできない接続元", reverse}, {"拒否する登録国コード", list(v.Network.DeniedCountries)}, {"許可IP/CIDR", list(v.AllowedCIDRs)}, {"拒否IP/CIDR", list(v.DeniedCIDRs)}, {"既知クローラー", crawler}, {"拒否するUser-Agent", list(v.DeniedAgents)}}
}
