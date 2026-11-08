// 4万件の不変分類表で、国条件・板別/共通上書き・未制限の照合コストを比較する。
package bootstrap

import (
	"fmt"
	"net/netip"
	"oimobbs/internal/identity"
	"testing"
)

// countryBenchmarkClassifier は同じ4万prefixと登録国を測定対象へ供給する。
func countryBenchmarkClassifier(b testing.TB) *identity.NetworkClassifier {
	b.Helper()
	classifier := readingCountryClassifier(b, "biglobe", "US")
	rows := make([]identity.NetworkClass, 0, networkRowLimit)
	for i := 0; i < networkRowLimit-1; i++ {
		rows = append(rows, identity.NetworkClass{CIDR: fmt.Sprintf("198.18.%d.%d/32", i/256, i%256), Kind: "unknown", Label: "ﾜｶﾗﾝ", Suffix: "0", Provider: "freebit"})
	}
	rows = append(rows, identity.NetworkClass{CIDR: "198.51.100.0/24", Kind: "unknown", Label: "ﾜｶﾗﾝ", Suffix: "0", Provider: "biglobe"})
	var err error
	classifier.Automatic, err = identity.CompileNetworks(rows, networkRowLimit)
	if err != nil {
		b.Fatal(err)
	}
	countries := make([]identity.CountryNetwork, 0, len(rows))
	for _, row := range rows {
		countries = append(countries, identity.CountryNetwork{Prefix: netip.MustParsePrefix(row.CIDR), Code: "US"})
	}
	classifier.Access.Countries, err = identity.CompileCountries(countries)
	if err != nil {
		b.Fatal(err)
	}
	return classifier
}

// BenchmarkNetworkCountryPermission は投稿と閲覧で共用する実判定を測り、全反復で結果を照合する。
func BenchmarkNetworkCountryPermission(b *testing.B) {
	base := countryBenchmarkClassifier(b)
	ip := netip.MustParseAddr("198.51.100.8")
	for _, mode := range []string{"unrestricted", "automatic", "board", "common", "service", "foreign", "registered_japan", "registered_japan_foreign_provider", "vpn_guard"} {
		b.Run(mode, func(b *testing.B) {
			classifier := *base
			settings := &NetworkAccessSettings{AllowVPN: true, JapanOnly: mode != "unrestricted"}
			row := identity.NetworkClass{CIDR: "198.51.100.8/32", Kind: "unknown", Label: "ﾜｶﾗﾝ", Suffix: "0", Provider: "biglobe"}
			var local []identity.NetworkClass
			switch mode {
			case "board":
				local = []identity.NetworkClass{row}
			case "common":
				classifier.Overrides, _ = identity.CompileNetworks([]identity.NetworkClass{row}, 1)
			case "service":
				classifier.Services, _ = identity.CompileNetworks([]identity.NetworkClass{row}, 1)
			case "foreign":
				row.Provider = "aws"
				classifier.Automatic, _ = identity.CompileNetworks([]identity.NetworkClass{row}, 1)
			case "registered_japan", "registered_japan_foreign_provider":
				classifier.Access = &identity.AccessIndex{Countries: classifier.Access.Countries, Overrides: []identity.AccessOverride{{CIDR: "198.51.100.0/24", Country: "jp", VPN: "auto"}}}
				if mode == "registered_japan_foreign_provider" {
					row.Provider = "aws"
					classifier.Automatic, _ = identity.CompileNetworks([]identity.NetworkClass{row}, 1)
				}
			case "vpn_guard":
				settings.AllowVPN = false
			}
			b.ReportAllocs()
			for b.Loop() {
				allowed := checkNetworkPermission(&classifier, settings, ip, local) == nil
				if allowed != (mode != "foreign") {
					b.Fatal("unexpected permission result", mode, allowed)
				}
			}
		})
	}
}
