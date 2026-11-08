// 高速事業者判定と通常表示の板別・共通・特殊用途・サービス・自動表の優先順を照合する。
package bootstrap

import (
	"net/netip"
	"oimobbs/internal/identity"
	"testing"
)

func TestCountryPermissionProviderPrecedence(t *testing.T) {
	rows := []identity.NetworkClass{{}}
	for _, kind := range []string{"unknown", "hosting"} {
		for _, provider := range []string{"", "biglobe", "aws"} {
			rows = append(rows, identity.NetworkClass{CIDR: "198.51.100.0/24", Kind: kind, Label: "試験", Suffix: "0", Provider: provider})
		}
	}
	tables := make([]*identity.NetworkTable, len(rows))
	for i, row := range rows {
		if row.CIDR != "" {
			var err error
			tables[i], err = identity.CompileNetworks([]identity.NetworkClass{row}, 1)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	ip := netip.MustParseAddr("198.51.100.8")
	for _, auto := range tables {
		for _, common := range tables {
			for _, service := range tables {
				classifier := &identity.NetworkClassifier{Automatic: auto, Overrides: common}
				if service != nil {
					classifier.Services = service
				}
				for _, local := range rows {
					var board []identity.NetworkClass
					if local.CIDR != "" {
						board = []identity.NetworkClass{local}
					}
					provider := classifier.Classify(board, ip).Provider
					if got := domesticNetworkProvider(classifier, ip, board); got != domesticNetworkProviders[provider] {
						t.Fatal("provider precedence changed", local, provider, got)
					}
				}
			}
		}
	}
}
