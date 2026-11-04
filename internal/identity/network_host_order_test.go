// 複数PTRの照会順と重複による予算消費が、確認可能なサービス分類を妨げないことを検証する。
package identity

import (
	"context"
	"net/netip"
	"slices"
	"testing"
)

type orderedHostResolver struct {
	names    []string
	answers  map[string][]netip.Addr
	calls    []string
	expireOn string
	cancel   context.CancelFunc
}

func (r *orderedHostResolver) LookupAddr(context.Context, string) ([]string, error) {
	return r.names, nil
}

// LookupNetIP は指定名で共有の照会予算切れを再現し、実時間の待機を使わず照会順を記録する。
func (r *orderedHostResolver) LookupNetIP(ctx context.Context, _, name string) ([]netip.Addr, error) {
	r.calls = append(r.calls, name)
	if name == r.expireOn {
		r.cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.answers[name], nil
}

// TestHostServiceBeforeUnclassifiedBudget は一般名で予算を使い切る前に既知サービスを正引き確認する。
func TestHostServiceBeforeUnclassifiedBudget(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	resolver := &orderedHostResolver{
		names:    []string{"slow.example.", "SUBSCRIBER.VMOBILE.JP."},
		answers:  map[string][]netip.Addr{"subscriber.vmobile.jp": {ip}},
		expireOn: "slow.example", cancel: cancel,
	}
	got := inspectHost(ctx, resolver, ip)
	if got.class.Kind != "mvno" || got.class.Provider != "iij" || got.hostname != "subscriber.vmobile.jp" || got.status != HostDNSConfirmed {
		t.Fatalf("confirmable service lost to unrelated DNS: %+v; calls=%v", got, resolver.calls)
	}
	if !slices.Equal(resolver.calls, []string{"subscriber.vmobile.jp"}) || !slices.Equal(got.names, []string{"slow.example", "subscriber.vmobile.jp"}) {
		t.Fatal("unnecessary lookup or lost observation", resolver.calls, got.names)
	}
}

// TestHostLookupOrderAndDedup は正引き不一致の除外、候補内の順序、重複除去と一般名への補完を確認する。
func TestHostLookupOrderAndDedup(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	other := netip.MustParseAddr("1.1.1.1")
	for _, tc := range []struct {
		name, hostname, kind string
		names, calls         []string
		answers              map[string][]netip.Addr
		status               HostDNSStatus
	}{
		{"deduplicate", "", "", []string{"B.EXAMPLE.", "b.example", "a.example.", "A.EXAMPLE."}, []string{"b.example", "a.example"}, nil, HostDNSMismatch},
		{"unconfirmed service", "generic.example", "", []string{"generic.example.", "subscriber.vmobile.jp."}, []string{"subscriber.vmobile.jp", "generic.example"}, map[string][]netip.Addr{"subscriber.vmobile.jp": {other}, "generic.example": {ip}}, HostDNSConfirmed},
		{"first service", "subscriber.mineo.jp", "mvno", []string{"generic.example.", "subscriber.mineo.jp.", "subscriber.vmobile.jp."}, []string{"subscriber.mineo.jp"}, map[string][]netip.Addr{"subscriber.mineo.jp": {ip}, "subscriber.vmobile.jp": {ip}}, HostDNSConfirmed},
		{"second service", "subscriber.vmobile.jp", "mvno", []string{"subscriber.mineo.jp.", "subscriber.vmobile.jp."}, []string{"subscriber.mineo.jp", "subscriber.vmobile.jp"}, map[string][]netip.Addr{"subscriber.mineo.jp": {other}, "subscriber.vmobile.jp": {ip}}, HostDNSConfirmed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &orderedHostResolver{names: tc.names, answers: tc.answers}
			cache := NewHostCache(resolver)
			defer cache.Close()
			cache.Resolve(t.Context(), ip)
			class, classified := cache.Match(ip)
			observation, ok := cache.Observation(ip)
			if !ok || observation.Status != tc.status || observation.ConfirmedName != tc.hostname || classified != (tc.kind != "") || class.Kind != tc.kind || !slices.Equal(resolver.calls, tc.calls) || !cache.ReverseResolved(ip) {
				t.Fatalf("class=%+v observation=%+v calls=%v", class, observation, resolver.calls)
			}
		})
	}
}
