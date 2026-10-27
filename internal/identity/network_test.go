// 最長一致・非正規表記拒否・未知回線の非断定を検査する。
package identity

import (
	"net/netip"
	"testing"
)

func TestNetworkClassification(t *testing.T) {
	rows := []NetworkClass{{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0"}, {CIDR: "192.0.2.128/25", Kind: "mvno", Label: "ﾌﾞｰｲﾓ", Suffix: "M"}, {CIDR: "2001:db8::/32", Kind: "mobile", Label: "ｽﾌﾟｰ", Suffix: "d"}}
	if e := ValidateNetworks(rows); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct{ ip, kind, suffix string }{{"192.0.2.1", "fixed", "0"}, {"::ffff:192.0.2.200", "mvno", "M"}, {"2001:db8::1", "mobile", "d"}, {"198.51.100.1", "unknown", "0"}} {
		got := ClassifyNetwork(rows, netip.MustParseAddr(v.ip))
		if got.Kind != v.kind || got.Suffix != v.suffix {
			t.Fatal(v, got)
		}
	}
	for _, rows := range [][]NetworkClass{append(rows, rows[0]), {{CIDR: "192.0.2.1/24", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0"}}, {{CIDR: "2001:DB8::/32", Kind: "mobile", Label: "ｽﾌﾟｰ", Suffix: "d"}}, {{CIDR: "::ffff:192.0.2.0/120", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0"}}, {{CIDR: "192.0.2.0/24", Kind: "mobile", Label: "<x>", Suffix: "M"}}, {{CIDR: "192.0.2.0/24", Kind: "mobile", Label: "ﾜｯﾁｮｲ", Suffix: "MM"}}} {
		if ValidateNetworks(rows) == nil {
			t.Fatal("bad table accepted", rows)
		}
	}
}
