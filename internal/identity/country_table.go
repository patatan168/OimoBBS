// 登録国のprefixを不変索引にし、両familyで最長一致の国コードを返す。
package identity

import (
	"fmt"
	"net/netip"
	"slices"
)

// CountryNetwork は無料の登録国表の一範囲。Codeは英字2文字の登録国/地域コード。
type CountryNetwork struct {
	Prefix netip.Prefix
	Code   string
}

// CountryTable は構築後に変更しない国コード索引。
type CountryTable struct{ rows map[netip.Prefix]string }

// ValidCountryCode は空でない大文字英字2文字を検査する。
func ValidCountryCode(code string) bool {
	return len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z'
}

// CompileCountries は非正規prefix・重複・未知コード形式を拒否する。
func CompileCountries(rows []CountryNetwork) (*CountryTable, error) {
	if len(rows) == 0 || len(rows) > 300000 {
		return nil, fmt.Errorf("country row limit")
	}
	table := &CountryTable{rows: make(map[netip.Prefix]string, len(rows))}
	for _, r := range rows {
		p := r.Prefix
		if !p.IsValid() || p.Addr().Is4In6() || p != p.Masked() || !ValidCountryCode(r.Code) {
			return nil, fmt.Errorf("invalid country network")
		}
		if _, ok := table.rows[p]; ok {
			return nil, fmt.Errorf("duplicate country prefix")
		}
		table.rows[p] = r.Code
	}
	return table, nil
}

// Match はIPv4-mappedを正規化し、一致した国コードと範囲を返す。
func (t *CountryTable) Match(ip netip.Addr) (string, string, bool) {
	if t == nil || !ip.IsValid() || ip.Zone() != "" {
		return "", "", false
	}
	ip = ip.Unmap()
	for bits := ip.BitLen(); bits >= 0; bits-- {
		p := netip.PrefixFrom(ip, bits).Masked()
		if code, ok := t.rows[p]; ok {
			return code, p.String(), true
		}
	}
	return "", "", false
}

// Codes は取得済みの国・地域コードを重複なしの昇順で返す。
func (t *CountryTable) Codes() []string {
	if t == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, code := range t.rows {
		seen[code] = true
	}
	codes := make([]string, 0, len(seen))
	for code := range seen {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes
}
