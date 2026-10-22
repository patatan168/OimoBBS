// 無料の標準取得元を初期画面から一操作で保存・取得できることを検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"reflect"
	"strings"
	"testing"
)

func TestNetworkStandardSetup(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/refs/heads/master") {
			writeCountryFixture(w)
			return
		}
		if request.URL.Path == "/ipverse/geo-ip-blocks/master/country/jp/jp.json" {
			fmt.Fprint(w, `{"countryCode":"JP","prefixes":{"ipv4":["1.0.0.0/24"],"ipv6":["2400::/32"]}}`)
			return
		}
		if strings.HasSuffix(request.URL.Path, "/output/vpn/ipv4.txt") {
			fmt.Fprint(w, "2.0.0.0/24\n")
			return
		}
		if strings.HasSuffix(request.URL.Path, "/output/vpn/ipv6.txt") {
			fmt.Fprint(w, "2600::/32\n")
			return
		}
		var asn uint32
		if _, e := fmt.Sscanf(request.URL.Path, "/ipverse/as-ip-blocks/master/as/%d/aggregated.json", &asn); e != nil {
			http.NotFound(w, request)
			return
		}
		for index, preset := range networkSourcePresets {
			if asn == preset.ASN {
				fmt.Fprintf(w, `{"asn":%d,"prefixes":{"ipv4":["198.18.%d.0/24"],"ipv6":[]}}`, asn, index)
				return
			}
		}
		http.NotFound(w, request)
	}))
	defer feed.Close()
	r.mu.Lock()
	r.networkClient = networkTestClient(feed)
	r.mu.Unlock()
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	// 既存のカテゴリー・管理者上書きも標準導入で維持する。
	config := defaultNetworkConfig()
	config.IntervalHours = 72
	config.Categories = append(config.Categories, NetworkCategory{ID: "original", Name: "独自", Kind: "fixed", Label: "独自", Suffix: "0"})
	config.Overrides = []identity.NetworkClass{{CIDR: "198.18.0.1/32", Kind: "fixed", Label: "保存済み", Suffix: "0"}}
	get, _ := c.request("GET", "/api/v1/networks", "", nil)
	raw, _ := json.Marshal(config)
	res, body := c.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"network-before-standard"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	_, body = c.request("GET", "/networks", "", nil)
	if !strings.Contains(body, `<button type="submit">無料の標準データで更新を開始</button>`) {
		t.Fatal("missing enabled onboarding action")
	}
	common := pageFields(body)
	form := url.Values{"action": {"standard_setup"}, "csrf": {common.Get("csrf")}, "revision": {common.Get("revision")}, "request_id": {"network-standard-once"}}
	res, body = c.request("POST", "/networks", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 || !strings.Contains(body, "今すぐ更新") {
		t.Fatal(res.StatusCode, body)
	}
	fetched := waitNetworkAttempt(t, r, 0)
	if fetched.Error != "" || fetched.Count != len(networkSourcePresets) || !fetched.Config.Enabled || fetched.Config.IntervalHours != 24 || !reflect.DeepEqual(fetched.Config.Sources, defaultNetworkSources()) {
		t.Fatal(fetched)
	}
	if !reflect.DeepEqual(fetched.Config.Categories, config.Categories) || !reflect.DeepEqual(fetched.Config.Overrides, config.Overrides) {
		t.Fatal("standard setup replaced manual data")
	}
	probe, e := r.probeNetwork("198.18.0.1")
	if e != nil || probe.Class.Label != "保存済み" {
		t.Fatal(probe, e)
	}
	if _, e = networkFormConfig(fetched.Config, url.Values{"action": {"standard_setup"}}); e == nil {
		t.Fatal("existing sources overwritten")
	}
	res, _ = c.request("POST", "/networks", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 412 {
		t.Fatal("stale setup accepted", res.StatusCode)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	view, e := r.networkView()
	if e != nil || view.Count != len(networkSourcePresets) || view.CountryCount != 5 || view.JapanCount != 2 || view.VPN4Count != 1 || view.VPN6Count != 1 || !view.Config.Enabled || !reflect.DeepEqual(view.Config.Sources, defaultNetworkSources()) {
		t.Fatal(view, e)
	}
	if e = r.refreshNetworks(context.Background(), false); e != nil {
		t.Fatal(e)
	}
}
