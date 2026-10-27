// VPN事業者の取得・表示補完と、VPN判定をASN名から推測しない境界を検証する。
package bootstrap

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"oimobbs/internal/identity"
	"strings"
	"testing"
)

func TestVPNProviderFetchAndIndependentClassification(t *testing.T) {
	sources := []NetworkSource{}
	for _, s := range defaultNetworkSources() {
		for _, p := range vpnProviderPresets {
			if s.ASN == p.ASN {
				sources = append(sources, s)
			}
		}
	}
	client := &http.Client{Transport: networkTestTransport(func(req *http.Request) (*http.Response, error) {
		var asn uint32
		fmt.Sscanf(req.URL.Path, "/ipverse/as-ip-blocks/master/as/%d/aggregated.json", &asn)
		for i, p := range vpnProviderPresets {
			if asn == p.ASN {
				body := fmt.Sprintf(`{"asn":%d,"prefixes":{"ipv4":["198.18.%d.0/24"],"ipv6":["2001:db8:%x::/48"]}}`, asn, i, i+1)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			}
		}
		t.Errorf("unexpected ASN %d", asn)
		return nil, errNetworkFetch
	})}
	rows, err := fetchNetworkRows(t.Context(), client, sources)
	if err != nil || len(rows) != 2*len(vpnProviderPresets) {
		t.Fatal(len(rows), err)
	}
	automatic, err := identity.CompileNetworks(rows, networkRowLimit)
	if err != nil {
		t.Fatal(err)
	}
	vpn, err := identity.CompileNetworks([]identity.NetworkClass{{CIDR: "198.18.0.0/25", Kind: "vpn", Label: "ｺﾝﾆﾁﾜ", Suffix: "8"}, {CIDR: "2001:db8:1::/49", Kind: "vpn", Label: "ｺﾝﾆﾁﾜ", Suffix: "8"}}, networkRowLimit)
	if err != nil {
		t.Fatal(err)
	}
	classifier := &identity.NetworkClassifier{Automatic: automatic, Access: &identity.AccessIndex{VPN: vpn, VPN4Ready: true, VPN6Ready: true}}
	for _, tc := range []struct{ ip, kind, status string }{
		{"198.18.0.1", "vpn", "vpn"}, {"198.18.0.200", "unknown", "direct"},
		{"2001:db8:1::1", "vpn", "vpn"}, {"2001:db8:1:8000::1", "unknown", "direct"},
	} {
		ip := netip.MustParseAddr(tc.ip)
		display := classifier.Classify(nil, ip)
		if display.Kind != tc.kind || display.Provider != "m247" || classifier.ClassifyAccess(ip).VPN != tc.status {
			t.Fatalf("%s: %+v", tc.ip, display)
		}
	}
	for i, p := range vpnProviderPresets {
		ip := netip.MustParseAddr(fmt.Sprintf("198.18.%d.1", i))
		if got := classifier.Classify(nil, ip).Provider; got != presetProvider(p.ID) {
			t.Fatal(p.ID, got)
		}
	}
}
