// 国内事業者による閲覧の国制限補完と、独立した拒否条件・元の国情報の保持を検証する。
package bootstrap

import (
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/identity"
	"strings"
	"testing"
)

// readingCountryClassifier は架空のIP範囲で事業者と登録国を独立して設定する。
func readingCountryClassifier(t testing.TB, provider, code string, prefix ...string) *identity.NetworkClassifier {
	t.Helper()
	row := identity.NetworkClass{CIDR: "198.51.100.0/24", Kind: "unknown", Label: "事業者", Suffix: "0", Provider: provider}
	if len(prefix) > 0 {
		row.CIDR = prefix[0]
	}
	automatic, err := identity.CompileNetworks([]identity.NetworkClass{row}, 1)
	if err != nil {
		t.Fatal(err)
	}
	access := &identity.AccessIndex{VPN4Ready: true}
	if code != "" {
		access.Countries, err = identity.CompileCountries([]identity.CountryNetwork{{Prefix: netip.MustParsePrefix(row.CIDR), Code: code}})
		if err != nil {
			t.Fatal(err)
		}
	}
	return &identity.NetworkClassifier{Automatic: automatic, Access: access}
}

// TestReadingDomesticHTTP は実HTTP/2で国外登録・未登録・確認済みDNSと拒否条件を検証する。
func TestReadingDomesticHTTP(t *testing.T) {
	// 予約済み範囲はDNS照会対象外なので、既存DNS試験と同じ公開アドレスへ模擬分類だけを割り当てる。
	ip := netip.MustParseAddr("8.8.8.8")
	for _, tc := range []struct {
		name, provider, code string
		resolver             probeDNSResolver
		denial               string
		status               int
	}{
		{"foreign domestic", "biglobe", "US", probeDNSResolver{}, "", 200},
		{"unknown domestic", "biglobe", "", probeDNSResolver{}, "", 200},
		{"foreign provider", "aws", "US", probeDNSResolver{}, "", 403},
		{"confirmed DNS", "", "US", probeDNSResolver{names: []string{"subscriber.ppp.ocn.ne.jp."}, ips: []netip.Addr{ip}}, "", 200},
		{"unconfirmed DNS", "", "US", probeDNSResolver{names: []string{"subscriber.ppp.ocn.ne.jp."}, ips: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, "", 403},
		{"line rejection", "biglobe", "US", probeDNSResolver{}, "line", 403},
		{"VPN rejection", "biglobe", "US", probeDNSResolver{}, "vpn", 403},
		{"Japan rejection", "biglobe", "US", probeDNSResolver{}, "JP", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, repo := adminFixture(t)
			defer repo.Close()
			repo.networkHosts.Close()
			repo.networkHosts = identity.NewHostCache(tc.resolver)
			classifier := readingCountryClassifier(t, tc.provider, tc.code, "8.8.8.0/24")
			classifier.Services = repo.networkHosts
			p := defaultReadingPolicy()
			p.Enabled = true
			p.Network.JapanOnly = true
			p.Network.DeniedCountries = []string{"US"}
			switch tc.denial {
			case "line":
				p.Network.DeniedKinds = []string{"unknown"}
			case "vpn":
				p.Network.AllowVPN = false
				classifier.Access.VPN = classifier.Automatic
			case "JP":
				p.Network.DeniedCountries = []string{"JP"}
			}
			repo.liveNetworks.Store(classifier)
			policy, err := compileReadingPolicy(p)
			if err != nil {
				t.Fatal(err)
			}
			repo.liveReading.Store(&readingSnapshot{Policies: map[string]*compiledReadingPolicy{"site": policy}})
			handler := repo.SiteWebHandler(nil)
			server := modernHTTPTestServer(t, &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.RemoteAddr = ip.String() + ":12345"
				handler.ServeHTTP(w, r)
			})})
			defer server.Close()
			origin, _ := url.Parse(repo.cfg.Public.BaseURL)
			for _, method := range []string{"GET", "HEAD"} {
				for _, path := range []string{"/", "/bbsmenu.json", "/search"} {
					req, _ := http.NewRequestWithContext(t.Context(), method, server.URL+path, nil)
					req.Host = origin.Host
					req.Header.Set("Accept-Encoding", "gzip;q=0.1")
					res, err := server.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(res.Body)
					res.Body.Close()
					if err != nil || res.StatusCode != tc.status || res.ProtoMajor != 2 || !strings.Contains(res.Header.Get("Cache-Control"), "no-store") || method == "HEAD" && len(body) > 0 {
						t.Fatalf("%s %s: %s %d %s (%v)", method, path, res.Proto, res.StatusCode, body, err)
					}
				}
			}
		})
	}
}

// TestReadingDomesticCountry は閲覧・投稿で国内事業者だけをJPとして国条件へ渡し、登録国を維持する。
func TestReadingDomesticCountry(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.8")
	for _, tc := range []struct {
		provider string
		allow    bool
	}{
		{"biglobe", true}, {"ocn", true}, {"freebit", true}, {"wi2", true},
		{"sakura", true}, {"sinet", true}, {"gmobb", true}, {"bmobile", true},
		{"aws", false}, {"starlink", false}, {"m247", false}, {"proton", false},
		{"", false}, {"biglobe.example", false},
	} {
		for _, code := range []string{"US", ""} {
			t.Run(tc.provider+"/"+code, func(t *testing.T) {
				classifier := readingCountryClassifier(t, tc.provider, code)
				before := classifier.ClassifyAccess(ip)
				p := defaultReadingPolicy()
				p.Enabled = true
				p.Network.JapanOnly = true
				p.Network.DeniedCountries = []string{"US"}
				policy, err := compileReadingPolicy(p)
				if err != nil {
					t.Fatal(err)
				}
				if allowed := policy.check(classifier, ip, "browser") == nil; allowed != tc.allow {
					t.Fatalf("provider %s, country %s: allowed=%v", tc.provider, code, allowed)
				}
				if got := classifier.ClassifyAccess(ip); got != before {
					t.Fatal("registered country mutated", before, got)
				}
				if allowed := checkNetworkPermission(classifier, &p.Network, ip) == nil; allowed != tc.allow {
					t.Fatal("reading and posting country restrictions disagree", allowed)
				}
				p.Network.JapanOnly = false
				policy, _ = compileReadingPolicy(p)
				if allowed := policy.check(classifier, ip, "browser") == nil; allowed != tc.allow {
					t.Fatal("country list disagrees with Japan-only decision", allowed)
				}
			})
		}
	}
}

// TestReadingDomesticOtherDenials は国内事業者でも国以外の拒否とJPの明示拒否を維持する。
func TestReadingDomesticOtherDenials(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.8")
	for _, kind := range []string{"JP", "VPN", "VPN unavailable", "line", "reverse", "CIDR", "allow list", "agent", "crawler"} {
		t.Run(kind, func(t *testing.T) {
			classifier := readingCountryClassifier(t, "biglobe", "US")
			p := defaultReadingPolicy()
			p.Enabled = true
			p.Network.JapanOnly = true
			agent := "browser"
			switch kind {
			case "JP":
				p.Network.DeniedCountries = []string{"JP"}
			case "VPN":
				p.Network.AllowVPN = false
				classifier.Access.VPN = classifier.Automatic
			case "VPN unavailable":
				p.Network.AllowVPN = false
				classifier.Access.VPN4Ready = false
			case "line":
				p.Network.DeniedKinds = []string{"unknown"}
			case "reverse":
				deny := true
				p.Network.DenyUnresolvedHost = &deny
			case "CIDR":
				p.DeniedCIDRs = []string{"198.51.100.0/24"}
			case "allow list":
				p.AllowedCIDRs = []string{"192.0.2.0/24"}
			case "agent":
				p.DeniedAgents = []string{"browser"}
			case "crawler":
				p.DenyCrawlers = true
				agent = "Googlebot"
			}
			policy, err := compileReadingPolicy(p)
			if err != nil || policy.check(classifier, ip, agent) == nil {
				t.Fatal("independent restriction bypassed", err)
			}
		})
	}
}

// TestReadingDomesticCatalogue は国内標準の全事業者を対象とし、国外VPN事業者の混入を拒否する。
func TestReadingDomesticCatalogue(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.8")
	for _, preset := range networkDomesticSourcePresets {
		classifier := readingCountryClassifier(t, presetProvider(preset.ID), "US")
		if !domesticNetworkProvider(classifier, ip) {
			t.Fatal("domestic provider missing", preset.ID)
		}
	}
	for _, preset := range vpnProviderPresets {
		classifier := readingCountryClassifier(t, presetProvider(preset.ID), "US")
		if domesticNetworkProvider(classifier, ip) {
			t.Fatal("foreign VPN provider admitted", preset.ID)
		}
	}
}

// TestReadingDomesticPriorityAndFamilies はIPv6・mapped IPv4と、板別/共通上書きの優先順を検査する。
func TestReadingDomesticPriorityAndFamilies(t *testing.T) {
	for _, address := range []string{"198.51.100.8", "::ffff:198.51.100.8", "2001:db8::8"} {
		t.Run(address, func(t *testing.T) {
			ip := netip.MustParseAddr(address)
			prefix := netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()).String()
			foreign := identity.NetworkClass{CIDR: prefix, Kind: "unknown", Label: "事業者", Suffix: "0", Provider: "aws"}
			domestic := foreign
			domestic.Provider = "biglobe"
			classifier := &identity.NetworkClassifier{}
			var err error
			classifier.Automatic, err = identity.CompileNetworks([]identity.NetworkClass{foreign}, 1)
			if err != nil {
				t.Fatal(err)
			}
			p := defaultReadingPolicy()
			p.Enabled, p.Network.JapanOnly = true, true
			policy, _ := compileReadingPolicy(p)
			if policy.check(classifier, ip, "browser") == nil || policy.check(classifier, ip, "browser", []identity.NetworkClass{domestic}) != nil {
				t.Fatal("board override leaked into site policy or did not apply")
			}
			classifier.Overrides, err = identity.CompileNetworks([]identity.NetworkClass{domestic}, 1)
			if err != nil || policy.check(classifier, ip, "browser") != nil {
				t.Fatal("common override not applied", err)
			}
			if policy.check(classifier, ip, "browser", []identity.NetworkClass{foreign}) == nil {
				t.Fatal("foreign board override did not take priority")
			}
		})
	}
}
