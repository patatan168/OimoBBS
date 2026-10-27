// 無料の全世界登録国表を有界tar読取りとZstandard保存で共通分類へ追加する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/netip"
	"oimobbs/internal/identity"
	"slices"
	"strings"
)

const countriesNetworkURL = "https://codeload.github.com/ipverse/country-ip-blocks/tar.gz/refs/heads/master"
const countryRowLimit = 300000
const countryConflictsReader uint32 = 101
const countryUnpackedLimit = 8 << 20

// fetchCountries はarchiveを展開先へ書かず、国別aggregated.jsonだけを有界に読む。
func fetchCountries(ctx context.Context, client *http.Client) (string, error) {
	raw, e := fetchNetworkBody(ctx, client, countriesNetworkURL)
	if e != nil {
		return "", e
	}
	rows, e := parseCountryArchive(ctx, raw)
	if e != nil {
		return "", e
	}
	return encodeCountries(rows)
}

// encodeCountries はfamily内でprefixをソートし、直前アドレスとの差をZstandard/base64で保存する。
func encodeCountries(rows []identity.CountryNetwork) (string, error) {
	if len(rows) == 0 || len(rows) > countryRowLimit {
		return "", errNetworkData
	}
	for _, r := range rows {
		p := r.Prefix
		if !p.IsValid() || p.Addr().Is4In6() || p != p.Masked() || !identity.ValidCountryCode(r.Code) {
			return "", errNetworkData
		}
	}
	slices.SortFunc(rows, func(a, b identity.CountryNetwork) int {
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}
		if bits := a.Prefix.Bits() - b.Prefix.Bits(); bits != 0 {
			return bits
		}
		return strings.Compare(a.Code, b.Code)
	})
	var body bytes.Buffer
	body.Grow(12 + len(rows)*19)
	body.WriteString("OCC1")
	for _, v4 := range []bool{true, false} {
		count := uint32(0)
		for _, r := range rows {
			if r.Prefix.Addr().Is4() == v4 {
				count++
			}
		}
		_ = binary.Write(&body, binary.BigEndian, count)
		previous := [16]byte{}
		for _, r := range rows {
			if r.Prefix.Addr().Is4() != v4 {
				continue
			}
			addr := r.Prefix.Addr().As16()
			start := 0
			if v4 {
				start = 12
			}
			for n := start; n < 16; n++ {
				body.WriteByte(addr[n] ^ previous[n])
			}
			body.WriteByte(byte(r.Prefix.Bits()))
			body.WriteString(r.Code)
			previous = addr
		}
	}
	return networkCountryCompression.compress(body.Bytes())
}

// decodeCountries は容量・CRC・magic・件数・family・末尾を検査して不変表を復元する。
func decodeCountries(value string) (*identity.CountryTable, int, error) {
	return decodedCountries.decode(value)
}

// decodeCountriesUncached は初見の保存byteを完全検査する。構築後の表は変更しない。
func decodeCountriesUncached(value string) (*identity.CountryTable, int, error) {
	if value == "" {
		return nil, 0, nil
	}
	body, e := decompressNetworkData(value, countryUnpackedLimit)
	if e != nil || len(body) < 12 || string(body[:4]) != "OCC1" {
		return nil, 0, errNetworkData
	}
	offset := 4
	rows := []identity.CountryNetwork{}
	for _, v4 := range []bool{true, false} {
		if len(body)-offset < 4 {
			return nil, 0, errNetworkData
		}
		count := int(binary.BigEndian.Uint32(body[offset : offset+4]))
		offset += 4
		width := 16
		if v4 {
			width = 4
		}
		if count > countryRowLimit-len(rows) || count > (len(body)-offset)/(width+3) {
			return nil, 0, errNetworkData
		}
		rows = slices.Grow(rows, count)
		previous := [16]byte{}
		for range count {
			addr := previous
			start := 16 - width
			for n := start; n < 16; n++ {
				addr[n] ^= body[offset]
				offset++
			}
			bits := int(body[offset])
			offset++
			code := string(body[offset : offset+2])
			offset += 2
			var ip netip.Addr
			if v4 {
				ip = netip.AddrFrom4([4]byte{addr[12], addr[13], addr[14], addr[15]})
			} else {
				ip = netip.AddrFrom16(addr)
			}
			if bits > ip.BitLen() || !ip.IsValid() {
				return nil, 0, errNetworkData
			}
			rows = append(rows, identity.CountryNetwork{Prefix: netip.PrefixFrom(ip, bits), Code: code})
			previous = addr
		}
	}
	if offset != len(body) {
		return nil, 0, errNetworkData
	}
	table, e := identity.CompileCountries(rows)
	if e != nil {
		return nil, 0, errNetworkData
	}
	return table, len(rows), nil
}

func compressNetworkData(body []byte) (string, error) { return compressNetworkZstd(body) }

// decompressNetworkData は展開爆弾・非正規base64・CRC・連結frame/後続データを拒否する。
func decompressNetworkData(value string, limit int) ([]byte, error) {
	raw, err := decodeNetworkBase64(value)
	if err != nil {
		return nil, errNetworkData
	}
	return decompressNetworkZstd(raw, limit)
}

// MarshalJSON は全世界表がある場合に既存prefix配列も圧縮し、制御frameの上限を維持する。
func (v networkAccessData) MarshalJSON() ([]byte, error) {
	type wire struct {
		Japan     []string `json:"japan"`
		VPN4      []string `json:"vpn4"`
		VPN6      []string `json:"vpn6"`
		Countries string   `json:"countries"`
		Packed    string   `json:"packed_prefixes"`
	}
	out := wire{Japan: v.Japan, VPN4: v.VPN4, VPN6: v.VPN6, Countries: v.Countries}
	if v.Countries != "" {
		old := struct {
			Japan []string `json:"japan"`
			VPN4  []string `json:"vpn4"`
			VPN6  []string `json:"vpn6"`
		}{v.Japan, v.VPN4, v.VPN6}
		raw, e := json.Marshal(old)
		if e != nil {
			return nil, e
		}
		out.Packed, e = networkPrefixCompression.compress(raw)
		if e != nil {
			return nil, e
		}
		out.Japan = nil
		out.VPN4 = nil
		out.VPN6 = nil
	}
	return json.Marshal(out)
}

func networkRequiresReader33(v networkState) bool {
	if v.AccessData != nil && v.AccessData.Countries != "" {
		return true
	}
	for _, s := range v.Config.Sources {
		if s.Type == "countries" {
			return true
		}
	}
	for _, r := range v.Config.AccessOverrides {
		if r.CountryCode != "" {
			return true
		}
	}
	return false
}

// networkRequiresCountryConflictsReader は重複する国表を旧readerが誤読しないための境界。
func networkRequiresCountryConflictsReader(v networkState) bool {
	if v.AccessData == nil {
		return false
	}
	table, _, err := decodeCountries(v.AccessData.Countries)
	return err == nil && table.HasDuplicatePrefixes()
}
