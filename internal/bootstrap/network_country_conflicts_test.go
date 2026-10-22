// 国の重複を含む配信データの取込・制限判定・耐久保存・reader境界を検証する。
package bootstrap

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"testing"
	"time"
)

// TestNetworkCountryConflictFetchAndRecovery は架空の国表だけで、日本優先と不明の再起動後の保持を確かめる。
func TestNetworkCountryConflictFetchAndRecovery(t *testing.T) {
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		z := gzip.NewWriter(w)
		tw := tar.NewWriter(z)
		for _, code := range []string{"us", "de", "jp"} {
			prefixes := map[string][]string{"ipv4": {"198.51.100.0/24", "203.0.113.0/24"}, "ipv6": {"2001:db8:1::/48", "2001:db8:2::/48"}}
			if code == "jp" {
				prefixes = map[string][]string{"ipv4": {"203.0.113.0/24"}, "ipv6": {"2001:db8:2::/48"}}
			}
			upper := map[string]string{"us": "US", "de": "DE", "jp": "JP"}[code]
			body, _ := json.Marshal(map[string]any{"countryCode": upper, "prefixes": prefixes})
			_ = tw.WriteHeader(&tar.Header{Name: "fixture/country/" + code + "/aggregated.json", Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg})
			_, _ = tw.Write(body)
		}
		_ = tw.Close()
		_ = z.Close()
	}))
	defer feed.Close()
	encoded, err := fetchCountries(context.Background(), networkTestClient(feed))
	if err != nil {
		t.Fatal(err)
	}
	table, _, err := decodeCountries(encoded)
	if err != nil || !table.HasDuplicatePrefixes() {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ip, code string }{{"198.51.100.1", ""}, {"203.0.113.1", "JP"}, {"2001:db8:1::1", ""}, {"2001:db8:2::1", "JP"}} {
		code, _, ok := table.Match(netip.MustParseAddr(tc.ip))
		if !ok || code != tc.code {
			t.Fatal(tc, code, ok)
		}
	}
	classifier := &identity.NetworkClassifier{Access: &identity.AccessIndex{Countries: table}}
	if err = checkNetworkPermission(classifier, &NetworkAccessSettings{JapanOnly: true, AllowVPN: true}, netip.MustParseAddr("198.51.100.1")); err != ErrNetworkUnavailable {
		t.Fatal("unknown must not pass Japan-only access", err)
	}
	if err = checkNetworkPermission(classifier, &NetworkAccessSettings{JapanOnly: true, AllowVPN: true}, netip.MustParseAddr("203.0.113.1")); err != nil {
		t.Fatal("Japan priority", err)
	}
	// 表のbyte順も取得元の列挙順に依存させない。
	a := []identity.CountryNetwork{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Code: "US"}, {Prefix: netip.MustParsePrefix("198.51.100.0/24"), Code: "DE"}}
	b := []identity.CountryNetwork{a[1], a[0]}
	one, _ := encodeCountries(a)
	two, _ := encodeCountries(b)
	if one != two {
		t.Fatal("unstable country encoding")
	}
	cfg, r := adminFixture(t)
	defer func() { _ = r.Close() }()
	next, err := loadNetworkState(r.site.State())
	if err != nil {
		t.Fatal(err)
	}
	next.Version = 1
	next.AccessData = &networkAccessData{Countries: encoded}
	next.LastAttempt = domain.Time(time.Now().UnixNano())
	next.LastSuccess = next.LastAttempt
	next.AttemptVersion = next.Version
	next.AppliedVersion = next.Version
	r.mu.Lock()
	err = r.publishNetworks(next, nil, "network_refresh", nil)
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var site siteState
	_ = json.Unmarshal(r.site.State().Rows["site:state"].Value, &site)
	if site.MinimumReader != countryConflictsReader {
		t.Fatal("missing reader boundary", site.MinimumReader)
	}
	if _, err = inspectSiteState(r.site.State(), site.ID, cfg.Public.BaseURL); err != nil {
		t.Fatal("site invariants", err)
	}
	// 同じ保存内容を古いreader宣言で通さない。
	state := r.site.State()
	state.Rows = maps.Clone(state.Rows)
	site.MinimumReader = countryConflictsReader - 1
	row := state.Rows["site:state"]
	row.Value, _ = json.Marshal(site)
	state.Rows["site:state"] = row
	if _, err = inspectSiteState(state, site.ID, cfg.Public.BaseURL); err == nil {
		t.Fatal("country conflicts without reader boundary accepted")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal("reopen", err)
	}
	defer restored.Close()
	saved, err := loadNetworkState(restored.site.State())
	if err != nil {
		t.Fatal(err)
	}
	index, err := compileAccessData(saved.AccessData, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := (&identity.NetworkClassifier{Access: index}).ClassifyAccess(netip.MustParseAddr("198.51.100.1"))
	if got.Country != "unknown" || got.CountryCode != "" {
		t.Fatalf("lost conflict on restart: %+v", got)
	}
}
