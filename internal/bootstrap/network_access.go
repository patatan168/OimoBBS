// 日本登録IPと既知VPNの無料データを独立して保存し、板の接続制限へつなぐ。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
	"slices"
	"strconv"
	"strings"
)

const japanNetworkURL = "https://raw.githubusercontent.com/ipverse/geo-ip-blocks/master/country/jp/jp.json"
const vpnNetworkURL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/"

// NetworkAccessSettings は板ごとの接続制限。初期値は国外・VPNとも許可する。
type NetworkAccessSettings struct {
	DenyUnresolvedHost *bool    `json:"deny_unresolved_host"`
	DeniedKinds        []string `json:"denied_kinds"`
	DeniedCountries    []string `json:"denied_countries"`
	JapanOnly          bool     `json:"japan_only"`
	AllowVPN           bool     `json:"allow_vpn"`
}

type networkAccessData struct {
	Countries string   `json:"countries"`
	Japan     []string `json:"japan"`
	VPN4      []string `json:"vpn4"`
	VPN6      []string `json:"vpn6"`
}

var ErrForeignIP = errors.New("posting requires Japanese IP")

// ErrUnresolvedHost は板が逆引き不可の接続元を拒否した場合に返す。
var ErrUnresolvedHost = errors.New("posting requires reverse DNS")
var ErrNetworkPermission = errors.New("board network permission denied")
var ErrVPNIP = errors.New("posting from known VPN denied")
var ErrNetworkUnavailable = errors.New("network classification unavailable")

// checkNetworkAccess は受理済み再送の確認後に新規投稿だけを規制する。認証済みcapは回線規制を免除する。
func (b *postingBoard) checkNetworkAccess(settings *NetworkAccessSettings, ip netip.Addr, capAuthenticated bool, boardNetworks ...[]identity.NetworkClass) error {
	if settings == nil || capAuthenticated {
		return nil
	}
	var t *identity.NetworkClassifier
	if b.liveNetworks != nil {
		t = b.liveNetworks.Load()
	}
	return checkNetworkPermission(t, settings, ip, boardNetworks...)
}

// checkNetworkPermission は投稿・閲覧で共通の回線条件を判定する。CAP免除は呼出し側の投稿処理だけで適用する。
func checkNetworkPermission(t *identity.NetworkClassifier, settings *NetworkAccessSettings, ip netip.Addr, boardNetworks ...[]identity.NetworkClass) error {
	if settings == nil {
		return nil
	}
	if settings.denyUnresolvedHost() {
		var reverse interface{ ReverseResolved(netip.Addr) bool }
		if t != nil {
			reverse, _ = t.Services.(interface{ ReverseResolved(netip.Addr) bool })
		}
		if reverse == nil || !reverse.ReverseResolved(ip) {
			return ErrUnresolvedHost
		}
	}
	a := t.ClassifyAccess(ip)
	if settings.JapanOnly {
		if a.Country == "unknown" {
			return ErrNetworkUnavailable
		}
		if a.Country != "jp" {
			return ErrForeignIP
		}
	}
	if !settings.AllowVPN {
		if a.VPN == "unknown" {
			return ErrNetworkUnavailable
		}
		if a.VPN == "vpn" {
			return ErrVPNIP
		}
	}
	if len(settings.DeniedCountries) > 0 {
		if a.CountryCode == "" {
			return ErrNetworkUnavailable
		}
		if slices.Contains(settings.DeniedCountries, a.CountryCode) {
			return ErrNetworkPermission
		}
	}
	if len(settings.DeniedKinds) > 0 {
		provider := t
		if t != nil {
			provider = &identity.NetworkClassifier{Automatic: t.Automatic, Overrides: t.Overrides, Services: t.Services}
		}
		var local []identity.NetworkClass
		if len(boardNetworks) > 0 {
			local = boardNetworks[0]
		}
		if slices.Contains(settings.DeniedKinds, provider.Classify(local, ip).Kind) {
			return ErrNetworkPermission
		}
	}
	return nil
}

// compileAccessPrefixes は登録国/VPNの有界prefix表を検査し、索引に変換する。nilは未取得。
func compileAccessPrefixes(values []string, v4 *bool) (*identity.NetworkTable, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) == 0 || len(values) > networkRowLimit {
		return nil, errNetworkData
	}
	rows := make([]identity.NetworkClass, 0, len(values))
	for _, cidr := range values {
		p, e := netip.ParsePrefix(cidr)
		if e != nil || v4 != nil && p.Addr().Is4() != *v4 {
			return nil, errNetworkData
		}
		rows = append(rows, identity.NetworkClass{CIDR: cidr, Kind: "unknown", Label: "ﾜｯﾁｮｲ", Suffix: "0"})
	}
	return identity.CompileNetworks(rows, networkRowLimit)
}

// compileAccessData は未取得と非掲載を区別した不変索引を構築する。
func compileAccessData(data *networkAccessData, overrides []identity.AccessOverride) (*identity.AccessIndex, error) {
	if identity.ValidateAccessOverrides(overrides) != nil {
		return nil, errNetworkData
	}
	out := &identity.AccessIndex{Overrides: append([]identity.AccessOverride(nil), overrides...)}
	if data == nil {
		return out, nil
	}
	if data.Japan == nil && data.VPN4 == nil && data.VPN6 == nil && data.Countries == "" {
		return nil, errNetworkData
	}
	var e error
	out.Countries, _, e = decodeCountries(data.Countries)
	if e != nil {
		return nil, e
	}
	out.Japan, e = compileAccessPrefixes(data.Japan, nil)
	if e != nil {
		return nil, e
	}
	v4, v6 := true, false
	if _, e = compileAccessPrefixes(data.VPN4, &v4); e != nil {
		return nil, e
	}
	if _, e = compileAccessPrefixes(data.VPN6, &v6); e != nil {
		return nil, e
	}
	rows := append(append([]string{}, data.VPN4...), data.VPN6...)
	if len(rows) > 0 {
		out.VPN, e = compileAccessPrefixes(rows, nil)
		if e != nil {
			return nil, e
		}
	}
	out.VPN4Ready = data.VPN4 != nil
	out.VPN6Ready = data.VPN6 != nil
	return out, nil
}

// fetchAccessData は標準取得元の両familyを検査する。一部失敗でも候補全体を公開しない。
func fetchAccessData(ctx context.Context, client *http.Client, sources []NetworkSource) (*networkAccessData, error) {
	var out *networkAccessData
	for _, s := range sources {
		if s.Type != "japan" && s.Type != "vpn" && s.Type != "countries" {
			continue
		}
		if out == nil {
			out = &networkAccessData{}
		}
		if s.Type == "countries" {
			value, e := fetchCountries(ctx, client)
			if e != nil {
				return nil, e
			}
			out.Countries = value
		} else if s.Type == "japan" {
			raw, e := fetchNetworkBody(ctx, client, japanNetworkURL)
			if e != nil {
				return nil, e
			}
			var fields map[string]json.RawMessage
			if strictjson.Decode(raw, &fields) != nil {
				return nil, errNetworkData
			}
			var code string
			if json.Unmarshal(fields["countryCode"], &code) != nil || code != "JP" {
				return nil, errNetworkData
			}
			var prefixes struct {
				IPv4 []string `json:"ipv4"`
				IPv6 []string `json:"ipv6"`
			}
			if strictjson.Decode(fields["prefixes"], &prefixes) != nil || len(prefixes.IPv4) == 0 || len(prefixes.IPv6) == 0 {
				return nil, errNetworkData
			}
			v4, v6 := true, false
			if _, e = compileAccessPrefixes(prefixes.IPv4, &v4); e != nil {
				return nil, e
			}
			if _, e = compileAccessPrefixes(prefixes.IPv6, &v6); e != nil {
				return nil, e
			}
			out.Japan = append(prefixes.IPv4, prefixes.IPv6...)
		} else {
			for _, family := range []string{"ipv4", "ipv6"} {
				raw, e := fetchNetworkBody(ctx, client, vpnNetworkURL+family+".txt")
				if e != nil {
					return nil, e
				}
				values := []string{}
				for _, line := range strings.Split(string(raw), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					values = append(values, line)
				}
				v4 := family == "ipv4"
				if _, e = compileAccessPrefixes(values, &v4); e != nil {
					return nil, e
				}
				if v4 {
					out.VPN4 = values
				} else {
					out.VPN6 = values
				}
			}
		}
	}
	if _, e := compileAccessData(out, nil); e != nil {
		return nil, e
	}
	return out, nil
}

func hasAccessSources(sources []NetworkSource) bool {
	for _, s := range sources {
		if s.Type == "japan" || s.Type == "vpn" || s.Type == "countries" {
			return true
		}
	}
	return false
}

func defaultAccessSources() []NetworkSource {
	return []NetworkSource{{Name: "日本の登録IP（ipverse・無料）", Type: "japan"}, {Name: "既知VPN（X4BNet・無料）", Type: "vpn"}, {Name: "全世界の登録国（ipverse・無料）", Type: "countries"}}
}

// networkAccessMessage はWeb/専ブラで同じ制限理由を返し、外部サービスのエラーを公開しない。
func networkAccessMessage(e error) (string, int) {
	switch {
	case errors.Is(e, ErrUnresolvedHost):
		return "この板では、逆引きを確認できない接続元からの投稿を許可していません。", 403
	case errors.Is(e, ErrForeignIP):
		return "この板は日本の登録IPからのみ投稿できます。", 403
	case errors.Is(e, ErrNetworkPermission):
		return "この板では、この登録国または回線種別からの投稿を許可していません。", 403
	case errors.Is(e, ErrVPNIP):
		return "この板は既知のVPNからの投稿を許可していません。", 403
	case errors.Is(e, ErrNetworkUnavailable):
		return "接続元の判定データが未取得、または判定不能のため投稿できません。管理者に確認してください。", 503
	}
	return "", 0
}

// AccessForm は国/VPNの通常編集フォームへ保存値またはエラー時の入力を戻す。
func (p networksPage) AccessForm(index int, row identity.AccessOverride) networkRowForm {
	fields := url.Values{"index": {strconv.Itoa(index)}, "cidr": {row.CIDR}, "country": {row.Country}, "country_code": {row.CountryCode}, "vpn": {row.VPN}}
	if p.Fields.Get("action") == "access_save" && p.Fields.Get("index") == strconv.Itoa(index) {
		fields = p.Fields
	}
	return networkRowForm{Page: p, Fields: fields}
}
func (p networksPage) NewAccessForm() networkRowForm {
	return p.AccessForm(-1, identity.AccessOverride{Country: "auto", VPN: "auto"})
}

// UnmarshalJSON は未取得のfamilyをnullで保存し、空の取得成功表とは区別する。
func (v *networkAccessData) UnmarshalJSON(raw []byte) error {
	var fields struct {
		Japan     *[]string `json:"japan"`
		VPN4      *[]string `json:"vpn4"`
		VPN6      *[]string `json:"vpn6"`
		Countries string    `json:"countries"`
		Packed    string    `json:"packed_prefixes"`
	}
	if e := strictjson.Decode(raw, &fields); e != nil {
		return e
	}
	if fields.Packed != "" {
		if fields.Countries == "" || fields.Japan != nil || fields.VPN4 != nil || fields.VPN6 != nil {
			return errNetworkData
		}
		unpacked, e := decompressNetworkData(fields.Packed, 4<<20)
		if e != nil {
			return e
		}
		var lists struct {
			Japan *[]string `json:"japan"`
			VPN4  *[]string `json:"vpn4"`
			VPN6  *[]string `json:"vpn6"`
		}
		if e = strictjson.Decode(unpacked, &lists); e != nil {
			return errNetworkData
		}
		fields.Japan, fields.VPN4, fields.VPN6 = lists.Japan, lists.VPN4, lists.VPN6
	}
	*v = networkAccessData{Countries: fields.Countries}
	if fields.Japan != nil {
		v.Japan = *fields.Japan
	}
	if fields.VPN4 != nil {
		v.VPN4 = *fields.VPN4
	}
	if fields.VPN6 != nil {
		v.VPN6 = *fields.VPN6
	}
	return nil
}

func networkRowsRequire32(rows []identity.NetworkClass) bool {
	for _, r := range rows {
		if r.Kind == "vpn" || r.Kind == "foreign" {
			return true
		}
	}
	return false
}
func networkRequiresReader32(v networkState) bool {
	if v.AccessData != nil || hasAccessSources(v.Config.Sources) || len(v.Config.AccessOverrides) > 0 || networkRowsRequire32(v.Rows) || networkRowsRequire32(v.Config.Overrides) {
		return true
	}
	for _, s := range v.Config.Sources {
		if s.Kind == "vpn" || s.Kind == "foreign" {
			return true
		}
	}
	for _, c := range v.Config.Categories {
		if c.Kind == "vpn" || c.Kind == "foreign" {
			return true
		}
	}
	return false
}
func ruleRequiresReader32(rows []denialCondition) bool {
	for _, c := range rows {
		if c.Field == "line" && (c.Value == "vpn" || c.Value == "foreign") {
			return true
		}
	}
	return false
}

// denyUnresolvedHost は未設定の制限を許可として扱い、明示した拒否だけを有効にする。
func (v *NetworkAccessSettings) denyUnresolvedHost() bool {
	return v != nil && v.DenyUnresolvedHost != nil && *v.DenyUnresolvedHost
}
