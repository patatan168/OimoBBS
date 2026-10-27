// DNSの確定失敗と一時障害を分離し、5ch風のh/H表示と既存分類・上書きの優先順位を検証する。
package identity

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

type statusResolver struct {
	names      []string
	reverseErr error
	ips        []netip.Addr
	forwardErr error
}

func (r statusResolver) LookupAddr(context.Context, string) ([]string, error) {
	return r.names, r.reverseErr
}
func (r statusResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.ips, r.forwardErr
}

func TestHostDNSStatusDistinguishesDefinitiveAndTemporaryResults(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	missing := &net.DNSError{Err: "no such host", IsNotFound: true}
	temporary := &net.DNSError{Err: "temporary failure", IsTemporary: true}
	for _, tc := range []struct {
		name     string
		resolver statusResolver
		status   HostDNSStatus
		reverse  bool
	}{
		{"no PTR", statusResolver{}, HostDNSAbsent, false},
		{"NXDOMAIN", statusResolver{reverseErr: missing}, HostDNSAbsent, false},
		{"reverse timeout", statusResolver{reverseErr: context.DeadlineExceeded}, HostDNSUnchecked, false},
		{"reverse SERVFAIL", statusResolver{reverseErr: temporary}, HostDNSUnchecked, false},
		{"invalid PTR", statusResolver{names: []string{"bad..example."}}, HostDNSMismatch, false},
		{"forward mismatch", statusResolver{names: []string{"dns.example."}, ips: []netip.Addr{netip.MustParseAddr("8.8.4.4")}}, HostDNSMismatch, true},
		{"forward missing", statusResolver{names: []string{"dns.example."}, forwardErr: missing}, HostDNSMismatch, true},
		{"forward timeout", statusResolver{names: []string{"dns.example."}, forwardErr: context.DeadlineExceeded}, HostDNSUnchecked, true},
		{"forward SERVFAIL", statusResolver{names: []string{"dns.example."}, forwardErr: temporary}, HostDNSUnchecked, true},
		{"confirmed unclassified", statusResolver{names: []string{"dns.example."}, ips: []netip.Addr{ip}}, HostDNSConfirmed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewHostCache(tc.resolver)
			defer c.Close()
			if c.DNSStatus(ip) != HostDNSUnchecked {
				t.Fatal("not looked up")
			}
			c.Resolve(t.Context(), ip)
			if c.DNSStatus(ip) != tc.status || c.ReverseResolved(ip) != tc.reverse {
				t.Fatal(c.DNSStatus(ip), c.ReverseResolved(ip))
			}
			if _, ok := c.Match(ip); ok {
				t.Fatal("diagnostic changed service classification")
			}
		})
	}
}

func TestDNSDisplayKeepsKindAndManualVPNSpecialPrecedence(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	p := netip.MustParsePrefix("8.8.8.0/24")
	countries, _ := CompileCountries([]CountryNetwork{{Prefix: p, Code: "JP"}})
	for _, tc := range []struct {
		resolver      statusResolver
		label, suffix string
	}{{statusResolver{}, "ｱﾝﾀﾀﾞﾚ", "h"}, {statusResolver{names: []string{"wrong.example."}, ips: []netip.Addr{netip.MustParseAddr("8.8.4.4")}}, "JP", "H"}, {statusResolver{reverseErr: context.DeadlineExceeded}, "ﾜｯﾁｮｲ", "0"}, {statusResolver{names: []string{"generic.example."}, ips: []netip.Addr{ip}}, "ﾜｯﾁｮｲ", "0"}} {
		c := NewHostCache(tc.resolver)
		c.Resolve(t.Context(), ip)
		classifier := &NetworkClassifier{Services: c, Access: &AccessIndex{Countries: countries}}
		got := classifier.Classify(nil, ip)
		if got.Label != tc.label || got.Suffix != tc.suffix || got.Kind != "unknown" {
			t.Fatal("unknown classification", got)
		}
		row := NetworkClass{CIDR: p.String(), Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0", Provider: "test"}
		classifier.Automatic, _ = CompileNetworks([]NetworkClass{row}, 1)
		got = classifier.Classify(nil, ip)
		if got.Label != tc.label || got.Suffix != tc.suffix || got.Kind != "fixed" || got.Provider != "test" {
			t.Fatal("kind/provider changed", got)
		}
		row.Label = "manual"
		classifier.Overrides, _ = CompileNetworks([]NetworkClass{row}, 1)
		if got = classifier.Classify(nil, ip); got.Label != "manual" || got.Suffix != "0" {
			t.Fatal("manual override", got)
		}
		classifier.Overrides = nil
		classifier.Access.VPN = classifier.Automatic
		classifier.Access.VPN4Ready = true
		if got = classifier.Classify(nil, ip); got.Kind != "vpn" || got.Suffix != "8" {
			t.Fatal("VPN precedence", got)
		}
		classifier.Access.VPN4Ready = false
		for _, kind := range []string{"hosting", "satellite"} {
			row.Kind = kind
			row.Label, row.Suffix = DefaultNetworkDisplay(kind)
			classifier.Automatic, _ = CompileNetworks([]NetworkClass{row}, 1)
			if got = classifier.Classify(nil, ip); got.Label != row.Label || got.Suffix != row.Suffix {
				t.Fatal("special precedence", got)
			}
		}
		c.clock = func() time.Time { return time.Now().Add(11 * time.Minute) }
		if c.DNSStatus(ip) != HostDNSUnchecked {
			t.Fatal("expired diagnostic remained")
		}
		c.Close()
	}
}
