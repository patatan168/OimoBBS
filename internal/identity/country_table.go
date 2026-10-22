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
type CountryTable struct {
	rows              map[netip.Prefix]string
	codes             []string
	duplicatePrefixes bool
}

// ValidCountryCode は空でない大文字英字2文字を検査する。
func ValidCountryCode(code string) bool {
	return len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z'
}

// CompileCountries は正規prefixを索引化する。同一範囲の国が異なれば不明、日本を含めば日本を優先する。
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
		if previous, ok := table.rows[p]; ok {
			table.duplicatePrefixes = true
			switch {
			case previous == "JP" || r.Code == "JP":
				table.rows[p] = "JP"
			case previous != r.Code:
				table.rows[p] = ""
			}
			continue
		}
		table.rows[p] = r.Code
	}
	seen := map[string]bool{}
	for _, code := range table.rows {
		if code != "" {
			seen[code] = true
		}
	}
	table.codes = make([]string, 0, len(seen))
	for code := range seen {
		table.codes = append(table.codes, code)
	}
	slices.Sort(table.codes)
	return table, nil
}

// Match は最長一致の国と範囲を返す。重複による不明は空コードとtrueで、広い範囲への再照合を止める。
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

// Codes は構築時に集計した国・地域コードの複製を、重複なしの昇順で返す。
func (t *CountryTable) Codes() []string {
	if t == nil {
		return nil
	}
	return slices.Clone(t.codes)
}

// HasDuplicatePrefixes は重複を含む保存表が新しい国判定規則を必要とするかを返す。
func (t *CountryTable) HasDuplicatePrefixes() bool { return t != nil && t.duplicatePrefixes }
