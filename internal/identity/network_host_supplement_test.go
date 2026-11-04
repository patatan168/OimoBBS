// 公式に用途が分かるサービスのDNS補完と、未確認・共有名前空間の境界を検証する。
package identity

import (
	"context"
	"net/netip"
	"testing"
)

// TestHostSupplementClassification はASNの不明分類を確認済みサービスで補完する。
func TestHostSupplementClassification(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, tc := range []struct{ host, kind, provider, label, suffix string }{
		{"subscriber.ppp.ocn.ne.jp.", "fixed", "ocn", "ﾜｯﾁｮｲ", "0"},
		{"8.8.8.8.bf.2iij.net.", "fixed", "iij", "ﾜｯﾁｮｲ", "0"},
		{"v-8-8-8-8.ub-freebit.net.", "hosting", "freebit", "ｸﾓﾉｳｴ", "V"},
		{"8-8-8-8.sample.ap.gmo-isp.jp.", "fixed", "gmobb", "ﾜｯﾁｮｲ", "0"},
		{"8.8.8.8.ap.gmobb-fix.jp.", "fixed", "gmobb", "ﾜｯﾁｮｲ", "0"},
		{"SUBSCRIBER.DCMISP.NE.JP.", "mobile", "docomo", "ｽﾌﾟｯｯ", "d"},
		{"8.8.8.8.dy.iij4u.or.jp.", "fixed", "iij", "ﾜｯﾁｮｲ", "0"},
		{"subscriber.v6connect.net.", "fixed", "asahi-net", "ﾜｯﾁｮｲ", "0"},
		{"ec2-8-8-8-8.ap-northeast-1.compute.amazonaws.com.", "hosting", "aws", "ｸﾓﾉｳｴ", "V"},
		{"ec2-8-8-8-8.compute-1.amazonaws.com.", "hosting", "aws", "ｸﾓﾉｳｴ", "V"},
		{"sample.japaneast.cloudapp.azure.com.", "hosting", "microsoft", "ｸﾓﾉｳｴ", "V"},
		{"sample.cloudapp.net.", "hosting", "microsoft", "ｸﾓﾉｳｴ", "V"},
		{"8.8.8.8.bc.googleusercontent.com.", "hosting", "gcp", "ｸﾓﾉｳｴ", "V"},
		{"sample.vs.sakura.ne.jp.", "hosting", "sakura", "ｸﾓﾉｳｴ", "V"},
		{"static.8.8.8.8.clients.your-server.de.", "hosting", "hetzner", "ｸﾓﾉｳｴ", "V"},
		{"sample.members.linode.com.", "hosting", "linode", "ｸﾓﾉｳｴ", "V"},
		{"8-8-8-8.ip.linodeusercontent.com.", "hosting", "linode", "ｸﾓﾉｳｴ", "V"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			for _, confirmed := range []bool{true, false} {
				forward := netip.MustParseAddr("1.1.1.1")
				if confirmed {
					forward = ip
				}
				cache := NewHostCache(&hostTestResolver{names: []string{tc.host}, ips: []netip.Addr{forward}})
				defer cache.Close()
				cache.Resolve(context.Background(), ip)
				automatic, err := CompileNetworks([]NetworkClass{{CIDR: "8.8.8.0/24", Kind: "unknown", Provider: "upstream", Label: "不明", Suffix: "0"}}, 1)
				if err != nil {
					t.Fatal(err)
				}
				classifier := &NetworkClassifier{Automatic: automatic, Services: cache}
				got := classifier.Classify(nil, ip)
				if !confirmed {
					if got.Kind != "unknown" || got.Provider != "upstream" {
						t.Fatal("unconfirmed service replaced unknown", got)
					}
					continue
				}
				want := NetworkClass{CIDR: "8.8.8.8/32", Kind: tc.kind, Provider: tc.provider, Label: tc.label, Suffix: tc.suffix}
				if got != want {
					t.Fatalf("got %+v, want %+v", got, want)
				}
				manual := NetworkClass{CIDR: "8.8.8.8/32", Kind: "business", Label: "手動", Suffix: "C"}
				classifier.Overrides, err = CompileNetworks([]NetworkClass{manual}, 1)
				if err != nil || classifier.Classify(nil, ip).Label != manual.Label {
					t.Fatal("common override lost priority", err)
				}
				manual.Label = "板別"
				if got := classifier.Classify([]NetworkClass{manual}, ip); got.Label != manual.Label {
					t.Fatal("board override lost priority", got)
				}
				classifier.Overrides = nil
				classifier.Access = &AccessIndex{VPN: automatic, VPN4Ready: true}
				if got := classifier.Classify(nil, ip); got.Kind != "vpn" {
					t.Fatal("VPN lost priority", got)
				}
				classifier.Access = &AccessIndex{Overrides: []AccessOverride{{CIDR: "8.8.8.8/32", Country: "foreign", CountryCode: "US", VPN: "direct"}}}
				if got := classifier.Classify(nil, ip); got.Kind != "foreign" || got.Label != "US" {
					t.Fatal("country lost priority", got)
				}
			}
		})
	}
}

// TestHostSupplementNamespaceBoundary は専用名以外を正引き確認だけで分類しないことを検証する。
func TestHostSupplementNamespaceBoundary(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, host := range []string{
		"subscriber.ocn.ne.jp", "subscriber.ppp.ocn.ne.jp.attacker.example",
		"subscriber.2iij.net", "subscriber.bf.2iij.net", "8.8.8.8.bf.2iij.net.attacker.example",
		"subscriber.ub-freebit.net", "8.8.8.8.ub-freebit.net", "v-8-8-8.ub-freebit.net",
		"v-8-8-8-8.ub-freebit.net.attacker.example", "subscriber.asahi-net.or.jp",
		"subscriber.gmo-isp.jp", "subscriber.ap.gmo-isp.jp", "8-8-8.sample.ap.gmo-isp.jp",
		"8-8-8-8.ap.gmo-isp.jp", "8-8-8-8.sample.ap.gmo-isp.jp.attacker.example",
		"subscriber.gmobb-fix.jp", "subscriber.ap.gmobb-fix.jp", "8.8.8.ap.gmobb-fix.jp",
		"8.8.8.8.ap.gmobb-fix.jp.attacker.example", "dcmisp.ne.jp",
		"subscriber.dcmisp.ne.jp.attacker.example", "subscriber.notdcmisp.ne.jp",
		"subscriber.iij4u.or.jp", "subscriber.dy.iij4u.or.jp", "8.8.8.dy.iij4u.or.jp",
		"8.8.8.8.dy.iij4u.or.jp.attacker.example", "v6connect.net", "subscriber.v6connect.net.attacker.example",
		"sample.amazonaws.com", "ec2-8-8-8-8.compute.amazonaws.com", "ec2-8-8-8-8.compute-1.amazonaws.com.attacker.example",
		"sample.azure.com", "sample.cloudapp.azure.com", "sample.japaneast.cloudapp.azure.com.attacker.example",
		"sample.cloudapp.net.attacker.example", "sample.googleusercontent.com", "sample.bc.googleusercontent.com",
		"8.8.8.8.bc.googleusercontent.com.attacker.example", "sample.sakura.ne.jp", "sample.vs.sakura.ne.jp.attacker.example",
		"sample.your-server.de", "sample.clients.your-server.de", "static.8.8.8.clients.your-server.de",
		"static.8.8.8.8.clients.your-server.de.attacker.example", "sample.linode.com", "sample.linodeusercontent.com",
		"sample.ip.linodeusercontent.com", "8-8-8-8.ip.linodeusercontent.com.attacker.example", "sample.members.linode.com.attacker.example",
	} {
		t.Run(host, func(t *testing.T) {
			got, _, _ := verifyHost(context.Background(), &hostTestResolver{names: []string{host}, ips: []netip.Addr{ip}}, ip)
			if got.Kind != "" {
				t.Fatal("shared or spoofed namespace classified", got)
			}
		})
	}
}
