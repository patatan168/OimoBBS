// HTTPS DNSの取得先・型・上限・失敗を外部通信なしで検証する。
package identity

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

type dnsRoundTrip func(*http.Request) (*http.Response, error)

func (f dnsRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGoogleHTTPSQueries(t *testing.T) {
	resolver := &GoogleHTTPSResolver{client: &http.Client{Transport: dnsRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "dns.google" || r.URL.Path != "/resolve" || r.URL.Query().Get("edns_client_subnet") != "0.0.0.0/0" {
			t.Fatal(r.URL)
		}
		kind := r.URL.Query().Get("type")
		raw := `{"Status":0,"Answer":[{"Type":1,"Data":"8.8.8.8"},{"Type":28,"Data":"2001:4860:4860::8888"}]}`
		if kind == "12" {
			name := r.URL.Query().Get("name")
			if name != "8.8.8.8.in-addr.arpa" && name != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.2.ip6.arpa" {
				t.Fatal(name)
			}
			raw = `{"Status":0,"Answer":[{"Type":12,"Data":"dns.google."},{"Type":5,"Data":"alias."}]}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}, nil
	})}}
	for _, ip := range []string{"8.8.8.8", "::ffff:8.8.8.8", "2400::1"} {
		names, err := resolver.LookupAddr(context.Background(), ip)
		if err != nil || len(names) != 1 || names[0] != "dns.google." {
			t.Fatal(names, err)
		}
	}
	ips, err := resolver.LookupNetIP(context.Background(), "ip", "dns.google")
	if err != nil || len(ips) != 2 || ips[0] != netip.MustParseAddr("8.8.8.8") || !ips[1].Is6() {
		t.Fatal(ips, err)
	}
}
func TestGoogleHTTPSFailures(t *testing.T) {
	for _, raw := range []string{`{}`, `{"Status":null}`, `{"Status":3}`, `{"Status":2}`, `{"Status":0,"TC":true}`, `{"Status":0,"Answer":[{"Type":1,"Data":"bad"}]}`, `{`, strings.Repeat("x", (64<<10)+1)} {
		resolver := &GoogleHTTPSResolver{client: &http.Client{Transport: dnsRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}, nil
		})}}
		if _, err := resolver.LookupNetIP(context.Background(), "ip4", "example.com"); err == nil {
			t.Fatal("invalid DNS response accepted")
		}
	}
	resolver := NewGoogleHTTPSResolver()
	if resolver.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirect permitted")
	}
}

func TestGoogleDNSNegativeStatusIsNotTemporaryFailure(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status HostDNSStatus
	}{{`{"Status":3}`, HostDNSAbsent}, {`{"Status":0}`, HostDNSAbsent}, {`{"Status":2}`, HostDNSUnchecked}} {
		resolver := &GoogleHTTPSResolver{client: &http.Client{Transport: dnsRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}}
		cache := NewHostCache(resolver)
		cache.Resolve(t.Context(), netip.MustParseAddr("8.8.8.8"))
		if got := cache.DNSStatus(netip.MustParseAddr("8.8.8.8")); got != tc.status {
			t.Fatal(tc.body, got)
		}
		cache.Close()
	}
}
