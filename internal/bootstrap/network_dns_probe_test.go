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
