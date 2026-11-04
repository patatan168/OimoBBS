// 管理画面/APIのDNS診断が、PTR取得と正引き一致を分けて表示することを検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/identity"
	"strings"
	"testing"
)

type probeDNSResolver struct {
	names []string
	ips   []netip.Addr
}

func (r probeDNSResolver) LookupAddr(context.Context, string) ([]string, error) { return r.names, nil }
func (r probeDNSResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.ips, nil
}

type serviceFirstProbeDNSResolver struct{ probeDNSResolver }

// LookupNetIP は無関係なPTRの予算切れと、確認に不要なIPv6照会を含む取得の失敗を再現する。
func (r serviceFirstProbeDNSResolver) LookupNetIP(ctx context.Context, network, name string) ([]netip.Addr, error) {
	if name == "unrelated.example" {
		<-ctx.Done()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "ip4" {
		return nil, context.DeadlineExceeded
	}
	return r.probeDNSResolver.LookupNetIP(ctx, network, name)
}

func TestDNSDiagnosticManagementProbe(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, tc := range []struct {
		status, label, suffix, text string
		resolver                    probeDNSResolver
	}{{"absent", "ｱﾝﾀﾀﾞﾚ", "h", "PTRなし", probeDNSResolver{}}, {"mismatch", "ZZ", "H", "正引き不一致", probeDNSResolver{names: []string{"wrong.example."}, ips: []netip.Addr{netip.MustParseAddr("8.8.4.4")}}}, {"confirmed", "ﾜｯﾁｮｲ", "0", "逆引きと正引きが一致", probeDNSResolver{names: []string{"unknown.example."}, ips: []netip.Addr{ip}}}} {
		t.Run(tc.status, func(t *testing.T) {
			_, r := adminFixture(t)
			defer r.Close()
			r.networkHosts.Close()
			r.networkHosts = identity.NewHostCache(tc.resolver)
			classifier := *r.liveNetworks.Load()
			classifier.Services = r.networkHosts
			r.liveNetworks.Store(&classifier)
			client := newAdminClient(t, r)
			defer client.server.Close()
			if client.login(adminTestSecret) != 303 {
				t.Fatal("login")
			}
			get, _ := client.request("GET", "/api/v1/networks", "", nil)
			res, body := client.request("POST", "/api/v1/networks/lookup", `{"ip":"8.8.8.8"}`, http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}})
			var envelope struct {
				Data networkProbe `json:"data"`
			}
			if res.StatusCode != 200 || json.Unmarshal([]byte(body), &envelope) != nil {
				t.Fatal(res.StatusCode, body)
			}
			if p := envelope.Data; p.DNSStatus != tc.status || p.Class.Label != tc.label || p.Class.Suffix != tc.suffix || p.Class.Kind != "unknown" {
				t.Fatal(p)
			}
			_, page := client.request("GET", "/networks", "", nil)
			hidden := pageFields(page)
			fields := url.Values{"csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {hidden.Get("request_id")}}
			fields.Set("action", "probe")
			fields.Set("ip", ip.String())
			res, page = client.request("POST", "/networks", url.Values(fields).Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
			if res.StatusCode != 200 || !strings.Contains(page, tc.text) || !strings.Contains(page, "DNS確認結果") || !strings.Contains(page, "<dd>"+tc.suffix+"</dd>") {
				t.Fatal(res.StatusCode, "diagnostic form missing")
			}
		})
	}
}

// TestSupplementedNetworkManagementProbe は管理API・通常フォームと回線規制へのDNS補完を確認する。
func TestSupplementedNetworkManagementProbe(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, tc := range []struct{ host, kind, provider, suffix string }{
		{"subscriber.ppp.ocn.ne.jp", "fixed", "ocn", "0"},
		{"8.8.8.8.bf.2iij.net", "fixed", "iij", "0"},
		{"v-8-8-8-8.ub-freebit.net", "hosting", "freebit", "V"},
		{"8-8-8-8.sample.ap.gmo-isp.jp", "fixed", "gmobb", "0"},
		{"8.8.8.8.ap.gmobb-fix.jp", "fixed", "gmobb", "0"},
		{"subscriber.dcmisp.ne.jp", "mobile", "docomo", "d"},
		{"8.8.8.8.dy.iij4u.or.jp", "fixed", "iij", "0"},
		{"subscriber.v6connect.net", "fixed", "asahi-net", "0"},
		{"ec2-8-8-8-8.ap-northeast-1.compute.amazonaws.com", "hosting", "aws", "V"},
		{"sample.japaneast.cloudapp.azure.com", "hosting", "microsoft", "V"},
		{"8.8.8.8.bc.googleusercontent.com", "hosting", "gcp", "V"},
		{"sample.vs.sakura.ne.jp", "hosting", "sakura", "V"},
		{"static.8.8.8.8.clients.your-server.de", "hosting", "hetzner", "V"},
		{"8-8-8-8.ip.linodeusercontent.com", "hosting", "linode", "V"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			_, repo := adminFixture(t)
			defer repo.Close()
			repo.networkHosts.Close()
			repo.networkHosts = identity.NewHostCache(serviceFirstProbeDNSResolver{probeDNSResolver{names: []string{"unrelated.example.", tc.host + ".", strings.ToUpper(tc.host) + "."}, ips: []netip.Addr{ip}}})
			classifier := *repo.liveNetworks.Load()
			classifier.Services = repo.networkHosts
			var err error
			classifier.Automatic, err = identity.CompileNetworks([]identity.NetworkClass{{CIDR: "8.8.8.0/24", Kind: "unknown", Provider: "upstream", Label: "不明", Suffix: "0"}}, 1)
			if err != nil {
				t.Fatal(err)
			}
			repo.liveNetworks.Store(&classifier)
			client := newAdminClient(t, repo)
			defer client.server.Close()
			if client.login(adminTestSecret) != 303 {
				t.Fatal("login")
			}
			get, _ := client.request("GET", "/api/v1/networks", "", nil)
			res, body := client.request("POST", "/api/v1/networks/lookup", `{"ip":"8.8.8.8"}`, http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}})
			var envelope struct {
				Data networkProbe `json:"data"`
			}
			if res.StatusCode != 200 || json.Unmarshal([]byte(body), &envelope) != nil {
				t.Fatal(res.StatusCode, body)
			}
			probe := envelope.Data
			if probe.Class.Kind != tc.kind || probe.Class.Provider != tc.provider || probe.Class.Suffix != tc.suffix || probe.DNSStatus != "confirmed" || probe.Hostname != tc.host || probe.Origin != "逆引き・正引きで確認したサービス" {
				t.Fatal(probe)
			}
			_, page := client.request("GET", "/networks", "", nil)
			hidden := pageFields(page)
			fields := url.Values{"action": {"probe"}, "ip": {ip.String()}, "csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {hidden.Get("request_id")}}
			res, page = client.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
			if res.StatusCode != 200 || !strings.Contains(page, tc.host) || !strings.Contains(page, "逆引き・正引きで確認したサービス") || !strings.Contains(page, "<dd>"+tc.suffix+"</dd>") {
				t.Fatal(res.StatusCode, "supplemented form result missing")
			}
			for _, denied := range []string{"unknown", tc.kind} {
				policy := &NetworkAccessSettings{AllowVPN: true, DeniedKinds: []string{denied}}
				if got := checkNetworkPermission(&classifier, policy, ip); (got == ErrNetworkPermission) != (denied == tc.kind) || got != nil && got != ErrNetworkPermission {
					t.Fatalf("denied=%s: %v", denied, got)
				}
			}
		})
	}
}
