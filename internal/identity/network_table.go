// 共通分類表を不変のprefix索引へ変換し、上書きと最長一致を外部通信なしで照合する。
package identity

import "net/netip"

// NetworkTable は用途ごとの分類表。構築後は変更せず、複数の投稿ワーカーから共有する。
type NetworkTable struct {
	rows map[netip.Prefix]NetworkClass
}

// CompileNetworks は有界の共通表を検査して不変索引を作る。重複prefixは拒否する。
func CompileNetworks(rows []NetworkClass, limit int) (*NetworkTable, error) {
	if e := validateNetworks(rows, limit); e != nil {
		return nil, e
	}
	t := &NetworkTable{rows: make(map[netip.Prefix]NetworkClass, len(rows))}
	for _, r := range rows {
		p, _ := netip.ParsePrefix(r.CIDR)
		t.rows[p] = r
	}
	return t, nil
}

// Match はIP family内で最長prefixを探す。未一致はfalse、IPv4-mappedは正規化する。
func (t *NetworkTable) Match(ip netip.Addr) (NetworkClass, bool) {
	if t == nil || !ip.IsValid() || ip.Zone() != "" {
		return NetworkClass{}, false
	}
	ip = ip.Unmap()
	for bits := ip.BitLen(); bits >= 0; bits-- {
		if r, ok := t.rows[netip.PrefixFrom(ip, bits).Masked()]; ok {
			return r, true
		}
	}
	return NetworkClass{}, false
}

// NetworkMatcher は確定済み候補を外部通信なしで照合する索引。
type NetworkMatcher interface {
	Match(netip.Addr) (NetworkClass, bool)
}

// NetworkClassifier は運営の共通上書きを自動取得表より優先する。
type NetworkClassifier struct {
	Automatic, Overrides *NetworkTable
	Services             NetworkMatcher
	Access               *AccessIndex
}

// Classify は板・共通上書き、国/VPN、確認済みサービス、自動表の順で分類する。
func (t *NetworkClassifier) Classify(board []NetworkClass, ip netip.Addr) NetworkClass {
	r := t.classifyDisplay(board, ip)
	if r.Provider == "" && t != nil {
		if source, ok := t.Automatic.Match(ip); ok {
			r.Provider = source.Provider
		}
	}
	return r
}

// classifyDisplay は表示の優先順位を適用し、プロバイダ補完は呼出元で行う。
func (t *NetworkClassifier) classifyDisplay(board []NetworkClass, ip netip.Addr) NetworkClass {
	if r := ClassifyNetwork(board, ip); r.CIDR != "" {
		return r
	}
	if t != nil {
		if r, ok := t.Overrides.Match(ip); ok {
			return r
		}
		access := t.ClassifyAccess(ip)
		if access.VPN == "vpn" {
			return NetworkClass{CIDR: access.VPNCIDR, Kind: "vpn", Label: "ｺﾝﾆﾁﾜ", Suffix: "8"}
		}
		if access.Country == "foreign" {
			label := access.CountryCode
			if label == "" {
				label = "ZZ"
			}
			return NetworkClass{CIDR: access.CountryCIDR, Kind: "foreign", Label: label, Suffix: "X"}
		}
		if t.Services != nil {
			if r, ok := t.Services.Match(ip); ok {
				return r
			}
		}
		if r, ok := t.Automatic.Match(ip); ok {
			return r
		}
	}
	return ClassifyNetwork(nil, ip)
}

// DefaultNetworkDisplay は入力省略時の回線名と末尾。IPから事業者を推測しない。
func DefaultNetworkDisplay(kind string) (string, string) {
	switch kind {
	case "mobile":
		return "ﾓﾊﾞｲﾙ", "S"
	case "mvno":
		return "ﾌﾞｰｲﾓ", "M"
	case "wifi":
		return "ﾜｲﾌｧｲ", "W"
	case "vpn":
		return "ｺﾝﾆﾁﾜ", "8"
	case "foreign":
		return "ZZ", "X"
	case "proxy":
		return "ﾌﾟﾛｷｼ", "P"
	default:
		return "ﾜｯﾁｮｲ", "0"
	}
}
