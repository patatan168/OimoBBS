// 照会元と同じIP familyだけで正引き確認し、無関係なfamilyの障害で分類を失わないことを検証する。
package identity

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// TestGoogleHostConfirmationIgnoresOtherFamilyFailure はA/AAAA片側の障害下でも一致するfamilyの分類を確認する。
func TestGoogleHostConfirmationIgnoresOtherFamilyFailure(t *testing.T) {
	for _, address := range []struct{ ip, kind string }{
		{"8.8.8.8", "1"},
		{"::ffff:8.8.8.8", "1"},
		{"2001:4860:4860::8888", "28"},
	} {
		for _, failure := range []string{"SERVFAIL", "NXDOMAIN", "HTTP error", "timeout"} {
			t.Run(address.ip+"/"+failure, func(t *testing.T) {
				ip := netip.MustParseAddr(address.ip)
				var kinds []string
				resolver := &GoogleHTTPSResolver{client: &http.Client{Transport: dnsRoundTrip(func(request *http.Request) (*http.Response, error) {
					kind := request.URL.Query().Get("type")
					kinds = append(kinds, kind)
					body := `{"Status":0,"Answer":[{"Type":12,"Data":"subscriber.vmobile.jp."}]}`
					status := http.StatusOK
					if kind == address.kind {
						if request.URL.Query().Get("name") != "subscriber.vmobile.jp" {
							t.Error("unexpected forward name", request.URL)
						}
						body = `{"Status":0,"Answer":[{"Type":` + address.kind + `,"Data":"` + ip.Unmap().String() + `"}]}`
					} else if kind != "12" {
						switch failure {
						case "SERVFAIL":
							body = `{"Status":2}`
						case "NXDOMAIN":
							body = `{"Status":3}`
						case "HTTP error":
							status = http.StatusServiceUnavailable
						case "timeout":
							return nil, context.DeadlineExceeded
						}
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
				})}}
				cache := NewHostCache(resolver)
				defer cache.Close()
				cache.Resolve(t.Context(), ip)
				class, ok := cache.Match(ip)
				if !ok || class.Kind != "mvno" || class.Provider != "iij" || cache.DNSStatus(ip) != HostDNSConfirmed || cache.Hostname(ip) != "subscriber.vmobile.jp" {
					t.Fatalf("other family broke confirmation: class=%+v status=%s queries=%v", class, cache.DNSStatus(ip), kinds)
				}
				if !slices.Equal(kinds, []string{"12", address.kind}) {
					t.Fatal("queried unrelated address family", kinds)
				}
			})
		}
	}
}

// TestGoogleHostRelevantFamilyFailure は必要なfamilyの不一致・障害・件数超過を成功へ読み替えないことを確認する。
func TestGoogleHostRelevantFamilyFailure(t *testing.T) {
	for _, address := range []struct{ ip, kind, other string }{
		{"8.8.8.8", "1", "1.1.1.1"},
		{"2001:4860:4860::8888", "28", "2606:4700:4700::1111"},
	} {
		record := `{"Type":` + address.kind + `,"Data":"` + address.ip + `"}`
		for _, tc := range []struct {
			name, body string
			status     HostDNSStatus
		}{
			{"NXDOMAIN", `{"Status":3}`, HostDNSMismatch},
			{"empty", `{"Status":0}`, HostDNSMismatch},
			{"SERVFAIL", `{"Status":2}`, HostDNSUnchecked},
			{"timeout", "", HostDNSUnchecked},
			{"invalid address", `{"Status":0,"Answer":[{"Type":` + address.kind + `,"Data":"bad"}]}`, HostDNSUnchecked},
			{"different address", `{"Status":0,"Answer":[{"Type":` + address.kind + `,"Data":"` + address.other + `"}]}`, HostDNSMismatch},
			{"too many addresses", `{"Status":0,"Answer":[` + strings.Repeat(record+",", 32) + record + `]}`, HostDNSUnchecked},
		} {
			t.Run(address.ip+"/"+tc.name, func(t *testing.T) {
				var kinds []string
				resolver := &GoogleHTTPSResolver{client: &http.Client{Transport: dnsRoundTrip(func(request *http.Request) (*http.Response, error) {
					kind := request.URL.Query().Get("type")
					kinds = append(kinds, kind)
					body := tc.body
					if kind == "12" {
						body = `{"Status":0,"Answer":[{"Type":12,"Data":"subscriber.vmobile.jp."}]}`
					} else if tc.name == "timeout" {
						return nil, context.DeadlineExceeded
					}
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
				})}}
				cache := NewHostCache(resolver)
				defer cache.Close()
				ip := netip.MustParseAddr(address.ip)
				cache.Resolve(t.Context(), ip)
				if _, ok := cache.Match(ip); ok || cache.DNSStatus(ip) != tc.status || cache.Hostname(ip) != "" || !cache.ReverseResolved(ip) {
					t.Fatalf("failed confirmation accepted: status=%s queries=%v", cache.DNSStatus(ip), kinds)
				}
				if !slices.Equal(kinds, []string{"12", address.kind}) {
					t.Fatal("queried unrelated address family", kinds)
				}
			})
		}
	}
}
