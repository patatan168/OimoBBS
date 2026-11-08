// 閲覧・投稿の国条件で、登録国が国外・不明でも確認済み国内事業者を日本として評価する。
package bootstrap

import (
	"net/netip"
	"oimobbs/internal/identity"
)

// domesticNetworkProviders は国内標準ASN・国内の特殊網・確認済みDNSの事業者キーだけを採用する。
// 外資系クラウド・衛星・VPN事業者は国内向けサービスの有無だけでは追加しない。
var domesticNetworkProviders = func() map[string]bool {
	providers := map[string]bool{}
	for _, preset := range networkDomesticSourcePresets {
		providers[presetProvider(preset.ID)] = true
	}
	for _, provider := range []string{"sakura", "sinet", "utnet", "nca5", "hepnet", "supercsi", "kyushu-u", "apan-jp", "wide-ai3", "jst", "gmobb", "bmobile"} {
		providers[provider] = true
	}
	return providers
}()

// domesticNetworkProvider は表示名やDNS診断表示を生成せず、回線分類と同じ優先順で事業者を取得する。
// サービス分類は正引き確認済みキャッシュだけを使い、未検証のホスト名や投稿入力を採用しない。
func domesticNetworkProvider(t *identity.NetworkClassifier, ip netip.Addr, local ...[]identity.NetworkClass) bool {
	if t == nil {
		return false
	}
	key, manual := manualNetworkProvider(t, ip, local...)
	if manual && key != "" {
		return domesticNetworkProviders[key]
	}
	automatic, _ := t.Automatic.Match(ip)
	if !manual && !identity.SpecialNetworkKind(automatic.Kind) && t.Services != nil {
		if service, ok := t.Services.Match(ip); ok && service.Provider != "" {
			return domesticNetworkProviders[service.Provider]
		}
	}
	return domesticNetworkProviders[automatic.Provider]
}

// manualNetworkProvider は板別・共通上書きを優先し、キー空欄でもサービス分類への上書き権を保持する。
func manualNetworkProvider(t *identity.NetworkClassifier, ip netip.Addr, local ...[]identity.NetworkClass) (string, bool) {
	if len(local) > 0 {
		if row := identity.ClassifyNetwork(local[0], ip); row.CIDR != "" {
			return row.Provider, true
		}
	}
	row, ok := t.Overrides.Match(ip)
	return row.Provider, ok
}

// networkPermissionAccess は閲覧・投稿の国条件だけを補完し、元の国表・VPN属性を変えない。
func networkPermissionAccess(t *identity.NetworkClassifier, settings *NetworkAccessSettings, ip netip.Addr, local ...[]identity.NetworkClass) identity.AccessAttributes {
	country := settings != nil && (settings.JapanOnly || len(settings.DeniedCountries) > 0)
	if settings == nil || !country && settings.AllowVPN {
		return identity.AccessAttributes{}
	}
	// 国だけを制限し国内事業者を確認できる場合、元の国や許可済みVPNの再照合は不要。
	if country && settings.AllowVPN {
		if domesticNetworkProvider(t, ip, local...) {
			return identity.AccessAttributes{Country: "jp", CountryCode: "JP"}
		}
		return t.ClassifyAccessAttributes(ip)
	}
	access := t.ClassifyAccessAttributes(ip)
	if country && access.Country != "jp" && domesticNetworkProvider(t, ip, local...) {
		access.Country, access.CountryCode = "jp", "JP"
	}
	return access
}

// readingNeedsDNS は国条件しかない場合も、国内事業者を確認する必要があれば既存の有界DNS取得を使う。
func readingNeedsDNS(p *compiledReadingPolicy, t *identity.NetworkClassifier, ip netip.Addr) bool {
	if p == nil || !p.Policy.Enabled {
		return false
	}
	network := p.Policy.Network
	if network.denyUnresolvedHost() || len(network.DeniedKinds) > 0 {
		return true
	}
	return (network.JapanOnly || len(network.DeniedCountries) > 0) && !domesticNetworkProvider(t, ip) && t.ClassifyAccessAttributes(ip).Country != "jp"
}
