// 国と既知VPNの判定を事業者分類から独立した不変索引で扱う。
package identity

import (
	"fmt"
	"net/netip"
	"slices"
)

// AccessOverride は国/VPNの誤判定を修正する。autoは自動表を維持する。
type AccessOverride struct {
	CountryCode string `json:"country_code"`
	CIDR        string `json:"cidr"`
	Country     string `json:"country"`
	VPN         string `json:"vpn"`
}

// AccessResult は登録国と公開VPNリストの判定。未取得はunknown、非掲載はdirectとする。
type AccessResult struct {
	CountryCode   string `json:"country_code"`
	Country       string `json:"country"`
	VPN           string `json:"vpn"`
	CountryCIDR   string `json:"country_cidr"`
	VPNCIDR       string `json:"vpn_cidr"`
	CountryOrigin string `json:"country_origin"`
	VPNOrigin     string `json:"vpn_origin"`
}

// AccessIndex は成功済みの日本/VPN表と管理者上書きを保持する。
type AccessIndex struct {
	Countries            *CountryTable
	Japan, VPN           *NetworkTable
	VPN4Ready, VPN6Ready bool
	Overrides            []AccessOverride
}

// ValidateAccessOverrides は有界な正規CIDRと独立した三状態の上書きを検査する。
func ValidateAccessOverrides(rows []AccessOverride) error {
	if len(rows) > 512 {
		return fmt.Errorf("too many access overrides")
	}
	seen := map[string]bool{}
	for _, r := range rows {
		p, e := netip.ParsePrefix(r.CIDR)
		if e != nil || p.Addr().Is4In6() || p != p.Masked() || p.String() != r.CIDR || seen[r.CIDR] || !slices.Contains([]string{"auto", "jp", "foreign"}, r.Country) || !slices.Contains([]string{"auto", "vpn", "direct"}, r.VPN) || r.Country == "auto" && r.VPN == "auto" || r.CountryCode != "" && (!ValidCountryCode(r.CountryCode) || r.Country == "auto" || r.Country == "jp" && r.CountryCode != "JP" || r.Country == "foreign" && r.CountryCode == "JP") {
			return fmt.Errorf("invalid access override")
		}
		seen[r.CIDR] = true
	}
	return nil
}

// ClassifyAccess は国とVPNを別々に照合する。各属性の明示上書きどうしは最長一致を優先する。
func (t *NetworkClassifier) ClassifyAccess(ip netip.Addr) AccessResult {
	out := AccessResult{Country: "unknown", VPN: "unknown", CountryOrigin: "未取得・判定不能", VPNOrigin: "未取得・判定不能"}
	if !ip.IsValid() || ip.Zone() != "" || t == nil || t.Access == nil {
		return out
	}
	ip = ip.Unmap()
	a := t.Access
	if ip.IsGlobalUnicast() && !ip.IsPrivate() {
		code, cidr, countryMatched := a.Countries.Match(ip)
		if countryMatched {
			if code != "" {
				out.Country = "foreign"
			}
			if code == "JP" {
				out.Country = "jp"
			}
			out.CountryCode = code
			out.CountryCIDR = cidr
			out.CountryOrigin = "全世界の登録国表"
			if code == "" {
				out.CountryOrigin = "登録国の重複により不明"
			}
		}
		if a.Japan != nil {
			if out.Country == "unknown" && !countryMatched {
				out.Country = "foreign"
				out.CountryOrigin = "日本の登録IP表に非掲載"
			}
			if row, ok := a.Japan.Match(ip); ok {
				out.CountryCIDR = row.CIDR
				out.Country = "jp"
				out.CountryCode = "JP"
				out.CountryOrigin = "日本の登録IP表"
			}
		}
		if ip.Is4() && a.VPN4Ready || ip.Is6() && a.VPN6Ready {
			out.VPN = "direct"
			out.VPNOrigin = "既知VPN表に非掲載"
			if row, ok := a.VPN.Match(ip); ok {
				out.VPNCIDR = row.CIDR
				out.VPN = "vpn"
				out.VPNOrigin = "既知VPN表"
			}
		}
	}
	countryBits, vpnBits := -1, -1
	countryIndex := -1
	for index, r := range a.Overrides {
		p, _ := netip.ParsePrefix(r.CIDR)
		if !p.Contains(ip) {
			continue
		}
		if r.Country != "auto" && p.Bits() > countryBits {
			countryIndex = index
			countryBits = p.Bits()
		}
		if r.VPN != "auto" && p.Bits() > vpnBits {
			out.VPNCIDR = r.CIDR
			out.VPN = r.VPN
			out.VPNOrigin = "管理者のVPN上書き（" + r.CIDR + "）"
			vpnBits = p.Bits()
		}
	}
	if countryIndex >= 0 {
		r := a.Overrides[countryIndex]
		out.CountryCIDR = r.CIDR
		out.Country = r.Country
		if r.CountryCode != "" {
			out.CountryCode = r.CountryCode
		} else if out.CountryCode == "JP" {
			out.CountryCode = ""
		}
		if r.Country == "jp" {
			out.CountryCode = "JP"
		}
		out.CountryOrigin = "管理者の国上書き（" + r.CIDR + "）"
	}

	return out
}
