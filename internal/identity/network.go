// 接続元IPを管理者の版付きCIDR表で分類し、回線表示の部品を確定する。
package identity

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// NetworkClass は管理者が検証して登録する回線分類。UAや投稿フォームから採用しない。
type NetworkClass struct {
	Provider string `json:"provider"`
	CIDR     string `json:"cidr"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	Suffix   string `json:"suffix"`
}

// ValidProvider は表示名と独立した安定識別キーを検査する。空欄は未分類を表す。
func ValidProvider(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:-", c)) {
			return false
		}
	}
	return true
}

// ValidNetworkKind は規制・設定で共用する回線種別を検査する。
func ValidNetworkKind(s string) bool {
	return slices.Contains([]string{"unknown", "fixed", "mixed", "mobile", "mvno", "wifi", "proxy", "vpn", "foreign", "academic", "school", "government", "business", "hosting", "satellite"}, s)
}

// ValidateNetworks は同prefixの重複・非正規CIDR・表示制御文字を保存前に拒否する。
func ValidateNetworks(rows []NetworkClass) error {
	return validateNetworks(rows, 512)
}

func validateNetworks(rows []NetworkClass, limit int) error {
	if len(rows) > limit {
		return errors.New("too many network classes")
	}
	seen := map[netip.Prefix]bool{}
	for _, r := range rows {
		if !ValidProvider(r.Provider) {
			return errors.New("invalid provider")
		}
		p, e := netip.ParsePrefix(r.CIDR)
		if e != nil || p.Addr().Is4In6() || p != p.Masked() || p.String() != r.CIDR || seen[p] || !ValidNetworkKind(r.Kind) || !utf8.ValidString(r.Label) || strings.TrimSpace(r.Label) == "" || utf8.RuneCountInString(r.Label) > 16 || len(r.Suffix) != 1 || !strings.Contains("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", r.Suffix) {
			return errors.New("invalid network class")
		}
		for _, c := range r.Label {
			if unicode.IsControl(c) || unicode.IsSpace(c) || strings.ContainsRune("()[]<>&\"'◆★●", c) {
				return errors.New("invalid network label")
			}
		}
		seen[p] = true
	}
	return nil
}

// ClassifyNetwork は最長prefix一致を返す。未分類を固定回線と断定せずunknownにする。
func ClassifyNetwork(rows []NetworkClass, ip netip.Addr) NetworkClass {
	out := NetworkClass{Kind: "unknown", Label: "ﾜｯﾁｮｲ", Suffix: "0"}
	if !ip.IsValid() || ip.Zone() != "" {
		return out
	}
	bits := -1
	for _, row := range rows {
		p, e := netip.ParsePrefix(row.CIDR)
		if e == nil && p.Bits() > bits && p.Contains(ip.Unmap()) {
			out, bits = row, p.Bits()
		}
	}
	return out
}

// SpecialNetworkKind は接続方式と区別する用途別の特殊回線区分を判定する。
func SpecialNetworkKind(kind string) bool {
	switch kind {
	case "academic", "school", "government", "business", "hosting", "satellite":
		return true
	default:
		return false
	}
}
