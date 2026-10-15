// 閲覧制限の共通・板・管理画面の独立性と、HTTP配信前の拒否を検証する。
package bootstrap

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"oimobbs/internal/delivery"
	"oimobbs/internal/identity"
	"strings"
	"testing"
)

func TestReadingPolicyCIDRAndUA(t *testing.T) {
	p := defaultReadingPolicy()
	p.Enabled = true
	p.AllowedCIDRs = []string{"192.0.2.0/24"}
	p.DeniedCIDRs = []string{"192.0.2.9/32"}
	p.DeniedAgents = []string{"bad-client"}
	v, err := compileReadingPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip, ua string
		allow  bool
	}{
		{"192.0.2.1", "browser", true}, {"192.0.2.9", "browser", false},
		{"198.51.100.1", "browser", false}, {"192.0.2.1", "BAD-CLIENT/1", false},
	} {
		if got := v.check(nil, netip.MustParseAddr(tc.ip), tc.ua) == nil; got != tc.allow {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
}

func TestReadingGateRejectsBeforeConditionalResponse(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	p := defaultReadingPolicy()
	p.Enabled = true
	p.DeniedCIDRs = []string{"192.0.2.0/24"}
	v, err := compileReadingPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	repo.liveReading.Store(&readingSnapshot{Policies: map[string]*compiledReadingPolicy{"site": v}})
	for _, method := range []string{"GET", "HEAD"} {
		for _, path := range []string{"/", "/bbsmenu.json", "/search", "/test/dat/123.dat"} {
			r := httptest.NewRequest(method, repo.cfg.Public.BaseURL+path, nil)
			r.RemoteAddr = "192.0.2.8:12345"
			r.Header.Set("Range", "bytes=0-10")
			r.Header.Set("If-None-Match", "*")
			w := httptest.NewRecorder()
			repo.SiteWebHandler(nil).ServeHTTP(w, r)
			if w.Code != 403 || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s %s: %d %v", method, path, w.Code, w.Header())
			}
			if method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD body")
			}
		}
	}
}

func TestReadingKindsCountriesAndVPN(t *testing.T) {
	p := defaultReadingPolicy()
	p.Enabled = true
	p.Network.JapanOnly = true
	p.Network.AllowVPN = false
	fixed, _ := identity.CompileNetworks([]identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0"}}, 512)
	p.Network.DeniedKinds = []string{"unknown"}
	policy, err := compileReadingPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		country, code, vpn string
		allow              bool
	}{{"jp", "JP", "direct", true}, {"foreign", "US", "direct", false}, {"jp", "JP", "vpn", false}, {"unknown", "", "direct", false}, {"jp", "JP", "unknown", false}} {
		classifier := &identity.NetworkClassifier{Overrides: fixed, Access: &identity.AccessIndex{Overrides: []identity.AccessOverride{{CIDR: "192.0.2.0/24", Country: tc.country, CountryCode: tc.code, VPN: tc.vpn}}}}
		if allowed := policy.check(classifier, netip.MustParseAddr("192.0.2.1"), "") == nil; allowed != tc.allow {
			t.Fatal(tc, allowed)
		}
	}
	p.Network.JapanOnly = false
	p.Network.AllowVPN = true
	p.Network.DeniedKinds = []string{}
	p.Network.DeniedCountries = []string{"US"}
	policy, _ = compileReadingPolicy(p)
	classifier := &identity.NetworkClassifier{Access: &identity.AccessIndex{Overrides: []identity.AccessOverride{{CIDR: "192.0.2.0/24", Country: "foreign", CountryCode: "US", VPN: "direct"}}}}
	if policy.check(classifier, netip.MustParseAddr("192.0.2.1"), "") == nil {
		t.Fatal("denied country")
	}
	p.Network.DeniedCountries = []string{}
	p.Network.DeniedKinds = []string{"unknown"}
	policy, _ = compileReadingPolicy(p)
	if policy.check(nil, netip.MustParseAddr("192.0.2.1"), "", []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0"}}) != nil {
		t.Fatal("local board classification ignored")
	}
}

func TestReadingStreamingRevocationThroughBandwidthAndReprint(t *testing.T) {
	for _, bandwidth := range []bool{false, true} {
		t.Run(fmt.Sprint(bandwidth), func(t *testing.T) {
			_, repo := adminFixture(t)
			defer repo.Close()
			body := []byte(strings.Repeat("x", 40000))
			fault := &publicationFaultWriter{header: http.Header{}}
			fault.afterWrite = func() {
				p := defaultReadingPolicy()
				p.Enabled = true
				p.DeniedCIDRs = []string{"192.0.2.0/24"}
				v, _ := compileReadingPolicy(p)
				repo.liveReading.Store(&readingSnapshot{Policies: map[string]*compiledReadingPolicy{"site": v}})
			}
			req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+"/", nil)
			req.RemoteAddr = "192.0.2.1:12345"
			var sent int
			var sendErr error
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gated, denied := repo.readingGate(w, r, "site")
				if denied {
					t.Fatal("gate")
				}
				protected := &reprintResponseWriter{ResponseWriter: gated}
				sent, sendErr = protected.WriteResponse(200, body)
				if err := http.NewResponseController(protected).Flush(); err == nil {
					t.Fatal("flush bypass")
				}
			})
			if bandwidth {
				scheduler, err := delivery.New(delivery.MaxBudgetBits)
				if err != nil {
					t.Fatal(err)
				}
				defer scheduler.Close()
				var interrupted any
				func() { defer func() { interrupted = recover() }(); scheduler.Wrap(handler).ServeHTTP(fault, req) }()
				if interrupted != http.ErrAbortHandler {
					t.Fatal("revoked stream was not aborted", interrupted)
				}
			} else {
				handler.ServeHTTP(fault, req)
			}
			if !errors.Is(sendErr, errReadingDenied) || len(fault.sizes) != 1 || sent != fault.sizes[0] || sent <= 0 || sent > delivery.Chunk || fault.flushes != 0 {
				t.Fatal("revocation boundary", sent, sendErr, fault.sizes, fault.flushes)
			}
		})
	}
}

func TestReadingAdminChangeDoesNotInvalidatePublicResponse(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+"/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	base := httptest.NewRecorder()
	w, denied := repo.readingGate(base, req, "site")
	if denied {
		t.Fatal("initial gate")
	}
	p := defaultReadingPolicy()
	p.Enabled = true
	p.AllowedCIDRs = []string{"127.0.0.0/8"}
	compiled, _ := compileReadingPolicy(p)
	repo.liveReading.Store(&readingSnapshot{Policies: map[string]*compiledReadingPolicy{"admin": compiled}})
	if n, err := w.Write([]byte("public body")); err != nil || n != 11 || base.Code != 200 {
		t.Fatal("admin configuration affected public response", base.Code, n, err)
	}
}
