// DNSの観測結果を後から書き換えず、未確認のPTR名も正引き確認済み名と区別して取得する。
package identity

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestHostObservationPreservesPTRAndSnapshot(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, tc := range []struct {
		name      string
		resolver  statusResolver
		status    HostDNSStatus
		confirmed string
	}{
		{"confirmed", statusResolver{names: []string{"DNS.EXAMPLE.", "dns.example."}, ips: []netip.Addr{ip}}, HostDNSConfirmed, "dns.example"},
		{"mismatch", statusResolver{names: []string{"DNS.EXAMPLE."}, ips: []netip.Addr{netip.MustParseAddr("8.8.4.4")}}, HostDNSMismatch, ""},
		{"forward failure", statusResolver{names: []string{"DNS.EXAMPLE."}, forwardErr: context.DeadlineExceeded}, HostDNSUnchecked, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := NewHostCache(tc.resolver)
			defer cache.Close()
			if _, ok := cache.Observation(ip); ok {
				t.Fatal("unobserved IP has a result")
			}
			cache.Resolve(t.Context(), ip)
			value, ok := cache.Observation(ip)
			if !ok || !reflect.DeepEqual(value.Names, []string{"dns.example"}) || value.Status != tc.status || value.ConfirmedName != tc.confirmed || value.ObservedAt.IsZero() || value.Resolver != "system" {
				t.Fatalf("unexpected DNS observation: %+v", value)
			}
			value.Names[0] = "changed.example"
			again, _ := cache.Observation(ip)
			if again.Names[0] != "dns.example" {
				t.Fatal("snapshot changed the cache")
			}
			cache.clock = func() time.Time { return again.ObservedAt.Add(11 * time.Minute) }
			if _, ok := cache.Observation(ip); ok {
				t.Fatal("expired result was reused")
			}
		})
	}
}
