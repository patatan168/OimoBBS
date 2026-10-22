// 国コードarchiveと圧縮保存の互換・破損拒否・管理/復旧への接続を検証する。
package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"testing"
)

// writeCountryFixture は実配信と同じarchive構造の国内/国外・両familyを返す。
func writeCountryFixture(w http.ResponseWriter) {
	z := gzip.NewWriter(w)
	tarWriter := tar.NewWriter(z)
	for code, body := range map[string]string{
		"jp": `{"countryCode":"JP","prefixes":{"ipv4":["1.1.0.0/16"],"ipv6":["2400::/32"]}}`,
		"us": `{"countryCode":"US","prefixes":{"ipv4":["2.2.0.0/16","3.3.0.0/16"],"ipv6":["2600::/32"]}}`,
	} {
		name := "country-ip-blocks-master/country/" + code + "/aggregated.json"
		_ = tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tarWriter.Write([]byte(body))
	}
	_ = tarWriter.Close()
	_ = z.Close()
}

func TestNetworkCountriesCodecAndOldFormatRefusal(t *testing.T) {
	rows := []identity.CountryNetwork{{Prefix: netip.MustParsePrefix("3.3.0.0/16"), Code: "US"}, {Prefix: netip.MustParsePrefix("2600::/32"), Code: "US"}, {Prefix: netip.MustParsePrefix("2400::/32"), Code: "JP"}, {Prefix: netip.MustParsePrefix("3.3.1.0/24"), Code: "DE"}}
	encoded, e := encodeCountries(rows)
	if e != nil {
		t.Fatal(e)
	}
	table, count, e := decodeCountries(encoded)
	if e != nil || count != 4 {
		t.Fatal(count, e)
	}
	for _, tc := range []struct{ ip, code string }{{"3.3.2.1", "US"}, {"::ffff:3.3.1.1", "DE"}, {"2600::1", "US"}, {"2400::1", "JP"}} {
		code, _, ok := table.Match(netip.MustParseAddr(tc.ip))
		if !ok || code != tc.code {
			t.Fatal(tc, code)
		}
	}
	c := &identity.NetworkClassifier{Access: &identity.AccessIndex{Countries: table}}
	overrides := []identity.AccessOverride{{CIDR: "3.3.0.0/16", Country: "jp", VPN: "auto"}, {CIDR: "3.3.1.0/24", Country: "foreign", VPN: "auto"}}
	for _, order := range [][]identity.AccessOverride{overrides, {overrides[1], overrides[0]}} {
		c.Access.Overrides = order
		if a := c.ClassifyAccess(netip.MustParseAddr("3.3.1.1")); a.Country != "foreign" || a.CountryCode != "DE" {
			t.Fatal("override order changed country code", a)
		}
	}
	raw, e := json.Marshal(networkAccessData{Countries: encoded, Japan: []string{"1.1.0.0/16"}, VPN4: []string{"2.2.0.0/16"}, VPN6: []string{"2600::/32"}})
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(raw, []byte("packed_prefixes")) {
		t.Fatal("prefix data was not compressed")
	}
	var restored networkAccessData
	if e = strictjson.Decode(raw, &restored); e != nil || restored.Countries != encoded || len(restored.Japan) != 1 || len(restored.VPN6) != 1 {
		t.Fatal(restored, e)
	}
	for _, bad := range []string{"not base64", encoded + "AAAA", encoded[:len(encoded)-4]} {
		if _, _, e := decodeCountries(bad); e == nil {
			t.Fatal("corrupt country data accepted")
		}
	}
	body, _ := decompressNetworkData(encoded, countryUnpackedLimit)
	for _, bad := range [][]byte{append(append([]byte{}, body...), 0), []byte("bad magic"), body[:len(body)-1]} {
		packed, _ := compressNetworkData(bad)
		if _, _, e := decodeCountries(packed); e == nil {
			t.Fatal("bad country layout accepted")
		}
	}
	if _, e := encodeCountries([]identity.CountryNetwork{rows[0], rows[0]}); e != nil {
		t.Fatal("same-country duplicate rejected", e)
	}
	legacy := `{"cidr":"3.3.0.0/16","country":"foreign","vpn":"auto"}`
	var override identity.AccessOverride
	if err := strictjson.Decode([]byte(legacy), &override); err == nil {
		t.Fatal("old access override accepted")
	}
	current, _ := json.Marshal(identity.AccessOverride{CIDR: "3.3.0.0/16", Country: "foreign", VPN: "auto"})
	if err := strictjson.Decode(current, &override); err != nil {
		t.Fatal("current access override", err)
	}
	for _, r := range []identity.AccessOverride{{CIDR: "3.3.0.0/16", Country: "auto", CountryCode: "US", VPN: "auto"}, {CIDR: "3.3.0.0/16", Country: "jp", CountryCode: "US", VPN: "auto"}, {CIDR: "3.3.0.0/16", Country: "foreign", CountryCode: "JP", VPN: "auto"}} {
		if identity.ValidateAccessOverrides([]identity.AccessOverride{r}) == nil {
			t.Fatal("invalid code override accepted")
		}
	}
}

func TestNetworkCountriesClassificationRecovery(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	feed := httpTestCountryFeed(t)
	defer feed.Close()
	r.mu.Lock()
	r.networkClient = networkTestClient(feed)
	r.mu.Unlock()
	c := newAdminClient(t, r)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page := c.request("GET", "/networks", "", nil)
	hidden := pageFields(page)
	fields := url.Values{"action": {"access_setup"}, "csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {"country-setup-0001"}}
	response, body := c.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	v := waitNetworkAttempt(t, r, 0)
	if v.CountryCount != 5 || v.Error != "" {
		t.Fatal(v)
	}
	probe, e := r.probeNetwork("3.3.2.1")
	if e != nil || probe.Class.Label != "US" || probe.Class.Suffix != "X" || probe.Access.CountryCode != "US" {
		t.Fatal(probe, e)
	}
	probe, e = r.probeNetwork("2.2.2.2")
	if e != nil || probe.Class.Label != "ｺﾝﾆﾁﾜ" || probe.Class.Suffix != "8" || probe.Access.CountryCode != "US" {
		t.Fatal(probe, e)
	}
	_, page = c.request("GET", "/networks", "", nil)
	hidden = pageFields(page)
	fields = url.Values{"action": {"access_save"}, "csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {"country-override-01"}, "index": {"-1"}, "cidr": {"3.3.2.1"}, "country": {"foreign"}, "country_code": {"de"}, "vpn": {"auto"}}
	response, body = c.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 200 || !strings.Contains(body, "DE") {
		t.Fatal(response.StatusCode, body)
	}
	if e = r.refreshNetworks(context.Background(), false); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	importCandidateAudit(t, r)
	candidate := filepath.Join(candidateParent(t), "network-countries")
	if _, e = r.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal(e)
	}
	c.server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	v, e = r.networkView()
	if e != nil || v.CountryCount != 5 {
		t.Fatal(v, e)
	}
	probe, e = r.probeNetwork("3.3.2.1")
	if e != nil || probe.Class.Label != "DE" || probe.Access.CountryCode != "DE" {
		t.Fatal(probe, e)
	}
	probe, e = r.probeNetwork("2600::1")
	if e != nil || probe.Access.CountryCode != "US" || probe.Class.Label != "ｺﾝﾆﾁﾜ" {
		t.Fatal(probe, e)
	}
}

func httpTestCountryFeed(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/refs/heads/master"):
			writeCountryFixture(w)
		case strings.HasSuffix(r.URL.Path, "/jp/jp.json"):
			fmt.Fprint(w, `{"countryCode":"JP","prefixes":{"ipv4":["1.1.0.0/16"],"ipv6":["2400::/32"]}}`)
		case strings.HasSuffix(r.URL.Path, "/vpn/ipv4.txt"):
			fmt.Fprint(w, "2.2.0.0/16\n")
		case strings.HasSuffix(r.URL.Path, "/vpn/ipv6.txt"):
			fmt.Fprint(w, "2600::/32\n")
		default:
			http.NotFound(w, r)
		}
	}))
}
