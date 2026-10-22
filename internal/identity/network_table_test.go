// 共通分類のprefix索引と、広い上書き・不明上書き・IPv6の優先順を検査する。
package identity

import (
	"net/netip"
	"testing"
)

func TestNetworkTablePriority(t *testing.T) {
	automatic, e := CompileNetworks([]NetworkClass{{CIDR: "192.0.2.128/25", Kind: "mobile", Label: "携帯", Suffix: "d"}, {CIDR: "2001:db8::/32", Kind: "mvno", Label: "MVNO", Suffix: "M"}}, 40000)
	if e != nil {
		t.Fatal(e)
	}
	overrides, e := CompileNetworks([]NetworkClass{{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "固定", Suffix: "0"}, {CIDR: "2001:db8:1::/48", Kind: "unknown", Label: "不明", Suffix: "0"}}, 512)
	if e != nil {
		t.Fatal(e)
	}
	classifier := &NetworkClassifier{Automatic: automatic, Overrides: overrides}
	board := []NetworkClass{{CIDR: "192.0.0.0/16", Kind: "wifi", Label: "WiFi", Suffix: "W"}}
	for _, tt := range []struct {
		ip, kind string
		board    []NetworkClass
	}{{"192.0.2.200", "fixed", nil}, {"::ffff:192.0.2.200", "fixed", nil}, {"192.0.2.200", "wifi", board}, {"2001:db8:1::1", "unknown", nil}, {"2001:db8:2::1", "mvno", nil}, {"198.51.100.1", "unknown", nil}} {
		if got := classifier.Classify(tt.board, netip.MustParseAddr(tt.ip)); got.Kind != tt.kind {
			t.Fatal(tt, got)
		}
	}
	if _, e = CompileNetworks([]NetworkClass{{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "固定", Suffix: "0"}, {CIDR: "192.0.2.0/24", Kind: "mobile", Label: "携帯", Suffix: "S"}}, 40000); e == nil {
		t.Fatal("conflict accepted")
	}
}
