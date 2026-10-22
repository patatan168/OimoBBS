// 特殊用途の確認済みDNSを分類し、偽装suffix・正引き不一致・一般企業ドメインの誤分類を拒否する。
package identity

import (
	"context"
	"net/netip"
	"testing"
)

func TestSpecialHostsRequireConfirmedNamespace(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.1")
	for _, tc := range []struct{ host, kind, suffix string }{{"client.example.ac.jp.", "academic", "6"}, {"client.example.ed.jp.", "school", "7"}, {"client.example.go.jp.", "government", "G"}, {"client.example.ac.jp.evil.test.", "", ""}, {"client.example.co.jp.", "", ""}} {
		r := &hostTestResolver{names: []string{tc.host}, ips: []netip.Addr{ip}}
		got, _, _ := verifyHost(context.Background(), r, ip)
		if got.Kind != tc.kind || got.Suffix != tc.suffix {
			t.Fatal(tc, got)
		}
		r.ips = []netip.Addr{netip.MustParseAddr("203.0.113.2")}
		got, _, _ = verifyHost(context.Background(), r, ip)
		if got.Kind != "" {
			t.Fatal("unconfirmed host accepted", got)
		}
	}
}

func TestSpecialNetworkDisplayKeepsCountryAndVPNIndependent(t *testing.T) {
	ip := netip.MustParseAddr("198.18.0.1")
	prefix := netip.MustParsePrefix("198.18.0.0/24")
	countries, err := CompileCountries([]CountryNetwork{{Prefix: prefix, Code: "US"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"hosting", "satellite"} {
		label, suffix := DefaultNetworkDisplay(kind)
		table, err := CompileNetworks([]NetworkClass{{CIDR: prefix.String(), Kind: kind, Label: label, Suffix: suffix, Provider: "test"}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		c := &NetworkClassifier{Automatic: table, Access: &AccessIndex{Countries: countries}}
		if got := c.Classify(nil, ip); got.Label != label || got.Suffix != suffix {
			t.Fatal("foreign hid special display", got)
		}
		if got := c.ClassifyAccess(ip); got.Country != "foreign" || got.CountryCode != "US" {
			t.Fatal("country policy changed", got)
		}
		c.Access.VPN = table
		c.Access.VPN4Ready = true
		if got := c.Classify(nil, ip); got.Kind != "vpn" || got.Suffix != "8" {
			t.Fatal("VPN priority changed", got)
		}
		override := NetworkClass{CIDR: prefix.String(), Kind: "fixed", Label: "manual", Suffix: "0"}
		if got := c.Classify([]NetworkClass{override}, ip); got.Label != "manual" {
			t.Fatal("manual priority changed", got)
		}
	}
}
