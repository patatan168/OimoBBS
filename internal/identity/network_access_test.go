// 国とVPNの独立判定・family境界・手動修正・表示の優先順を検査する。
package identity

import (
	"net/netip"
	"testing"
)

func TestNetworkAccessIndependentClassification(t *testing.T) {
	table := func(prefixes ...string) *NetworkTable {
		t.Helper()
		rows := []NetworkClass{}
		for _, p := range prefixes {
			rows = append(rows, NetworkClass{CIDR: p, Kind: "mobile", Label: "携帯", Suffix: "d"})
		}
		out, e := CompileNetworks(rows, 40000)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	c := &NetworkClassifier{Automatic: table("1.1.0.0/16"), Access: &AccessIndex{Japan: table("1.1.0.0/16", "2400::/32"), VPN: table("1.1.1.0/24", "2.2.0.0/16", "2400:0:1::/48"), VPN4Ready: true, VPN6Ready: true}}
	for _, tc := range []struct{ ip, country, vpn, kind string }{
		{"1.1.2.1", "jp", "direct", "mobile"}, {"::ffff:1.1.1.1", "jp", "vpn", "vpn"}, {"2.2.2.2", "foreign", "vpn", "vpn"}, {"3.3.3.3", "foreign", "direct", "foreign"}, {"2400:0:1::1", "jp", "vpn", "vpn"}, {"2400:0:2::1", "jp", "direct", "unknown"}, {"2600::1", "foreign", "direct", "foreign"}, {"127.0.0.1", "unknown", "unknown", "unknown"}, {"10.1.1.1", "unknown", "unknown", "unknown"},
	} {
		ip := netip.MustParseAddr(tc.ip)
		a := c.ClassifyAccess(ip)
		r := c.Classify(nil, ip)
		if a.Country != tc.country || a.VPN != tc.vpn || r.Kind != tc.kind {
			t.Fatalf("%s: %+v %+v", tc.ip, a, r)
		}
		if tc.kind == "vpn" && r.Suffix != "8" || tc.kind == "foreign" && r.Suffix != "X" {
			t.Fatalf("wrong ID suffix for %s: %+v", tc.ip, r)
		}
	}
	c.Access.Overrides = []AccessOverride{{CIDR: "1.1.0.0/16", Country: "foreign", VPN: "auto"}, {CIDR: "1.1.1.0/24", Country: "auto", VPN: "direct"}, {CIDR: "1.1.1.1/32", Country: "jp", VPN: "auto"}}
	if e := ValidateAccessOverrides(c.Access.Overrides); e != nil {
		t.Fatal(e)
	}
	a := c.ClassifyAccess(netip.MustParseAddr("1.1.1.1"))
	if a.Country != "jp" || a.VPN != "direct" {
		t.Fatal(a)
	}
	// 表示の上書きで接続元属性を変更できない。
	c.Overrides = table("2.2.0.0/16")
	ip := netip.MustParseAddr("2.2.2.2")
	if c.Classify(nil, ip).Kind != "mobile" || c.ClassifyAccess(ip).VPN != "vpn" {
		t.Fatal("display changed access decision")
	}
	c.Access.VPN6Ready = false
	if a = c.ClassifyAccess(netip.MustParseAddr("2400:0:1::1")); a.VPN != "unknown" {
		t.Fatal("missing family treated as direct", a)
	}
	for _, r := range []AccessOverride{{CIDR: "1.1.1.1/24", Country: "jp", VPN: "auto"}, {CIDR: "::ffff:1.1.1.1/128", Country: "jp", VPN: "auto"}, {CIDR: "1.1.1.1/32", Country: "auto", VPN: "auto"}, {CIDR: "1.1.1.1/32", Country: "Japan", VPN: "auto"}} {
		if ValidateAccessOverrides([]AccessOverride{r}) == nil {
			t.Fatal("invalid override", r)
		}
	}
	var nilClassifier *NetworkClassifier
	if nilClassifier.ClassifyAccess(ip).Country != "unknown" {
		t.Fatal("missing table")
	}
}
