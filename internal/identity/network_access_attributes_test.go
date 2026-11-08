// 根拠文字列を省く高速属性判定が、登録国・VPN・手動上書きの詳細判定と一致することを検証する。
package identity

import (
	"net/netip"
	"testing"
)

func TestAccessAttributesMatchDiagnostics(t *testing.T) {
	countries, err := CompileCountries([]CountryNetwork{
		{netip.MustParsePrefix("198.51.100.0/24"), "US"},
		{netip.MustParsePrefix("198.51.100.128/25"), "DE"},
		{netip.MustParsePrefix("198.51.100.128/25"), "FR"},
		{netip.MustParsePrefix("203.0.113.0/24"), "JP"},
		{netip.MustParsePrefix("2001:db8::/32"), "US"},
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn, _ := CompileNetworks([]NetworkClass{{CIDR: "198.51.100.0/25", Kind: "unknown", Label: "試験", Suffix: "0"}}, 1)
	classifier := &NetworkClassifier{Access: &AccessIndex{Countries: countries, VPN: vpn, VPN4Ready: true}}
	for _, overrides := range [][]AccessOverride{nil, {
		{CIDR: "198.51.100.0/24", Country: "jp", VPN: "auto"},
		{CIDR: "198.51.100.8/32", Country: "foreign", CountryCode: "DE", VPN: "direct"},
		{CIDR: "2001:db8::/32", Country: "jp", VPN: "vpn"},
	}} {
		classifier.Access.Overrides = overrides
		for _, address := range []string{"198.51.100.8", "::ffff:198.51.100.8", "198.51.100.129", "203.0.113.8", "192.0.2.8", "2001:db8::8", "10.0.0.1", "::1", "bad"} {
			ip, _ := netip.ParseAddr(address)
			detailed := classifier.ClassifyAccess(ip)
			want := AccessAttributes{CountryCode: detailed.CountryCode, Country: detailed.Country, VPN: detailed.VPN}
			if got := classifier.ClassifyAccessAttributes(ip); got != want {
				t.Fatal(address, got, want)
			}
		}
	}
	var absent *NetworkClassifier
	if got := absent.ClassifyAccessAttributes(netip.MustParseAddr("198.51.100.8")); got.Country != "unknown" || got.VPN != "unknown" || got.CountryCode != "" {
		t.Fatal(got)
	}
}
