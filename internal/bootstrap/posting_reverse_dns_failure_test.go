// DNSの不存在・不一致・一時障害でも投稿を受理し、原本に状態と取得できたPTRだけを残す。
package bootstrap

import (
	"context"
	"net/netip"
	"net/url"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"testing"
)

type unavailablePostingDNS struct{}

func (unavailablePostingDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, context.DeadlineExceeded
}
func (unavailablePostingDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, context.DeadlineExceeded
}

func TestPostingReverseDNSFailureDoesNotReject(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		resolver     identity.HostResolver
		names        int
	}{
		{"absent", "absent", probeDNSResolver{}, 0},
		{"mismatch", "mismatch", probeDNSResolver{names: []string{"wrong.example."}, ips: []netip.Addr{netip.MustParseAddr("8.8.4.4")}}, 1},
		{"temporary failure", "unchecked", unavailablePostingDNS{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			if _, err := Initialize(cfg, "DNS失敗"); err != nil {
				t.Fatal(err)
			}
			r, err := OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			useHealthyPostingCapacity(t, r)
			board, err := r.CreateBoard(t.Context(), "reverse", "逆引き")
			if err != nil {
				t.Fatal(err)
			}
			r.networkHosts.Close()
			r.networkHosts = identity.NewHostCache(tc.resolver)
			s := reverseDNSFormServer(t, r, board.ID)
			posted, err := sendForm(s, url.Values{"bbs": {"reverse"}, "subject": {"題"}, "MESSAGE": {"本文"}})
			s.Close()
			if err != nil || !posted.Accepted {
				t.Fatal("DNS failure rejected posting", posted, err)
			}
			rows := reverseDNSRecords(t, r, board.ID)
			if len(rows) != 1 {
				t.Fatal("missing accepted record")
			}
			selected, err := rows[0].Project([]string{"connection"})
			if err != nil {
				t.Fatal(err)
			}
			value := selected["connection"].(*evidence.HTTPObservation).ReverseDNS
			if value == nil || value.Status != tc.status || value.ConfirmedName != "" || len(value.Names) != tc.names {
				t.Fatalf("wrong failure record: %+v", value)
			}
		})
	}
}
