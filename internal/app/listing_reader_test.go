// 所有列外の一覧も、要約と送信権限を同じ世代から取得し期限・停止を引き継ぐ。
package app

import (
	"oimobbs/internal/domain"
	"testing"
)

func TestListingReaderGenerationAndRevocation(t *testing.T) {
	g := &publicationGate{leases: map[*PublicLease]func(){}}
	reader := (&PostingLog{gate: g}).PublicReader()
	summary := ThreadSummary{Created: 1, State: "active", Title: "first", Count: 2, BumpKind: "normal", BumpValue: 10}
	g.snapshot = &PostingSnapshot{gate: g, Expires: 100, DAT: []byte("confirmed\n"), summary: summary}
	s, publication, status := reader.Listing(1)
	if status != 200 || *s != summary || len(publication.DAT) != 0 {
		t.Fatal("listing metadata or DAT retained", s, status)
	}
	lease, err := publication.AcquirePublic(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	// 候補を交換しても取得済み要約と世代は書き換えない。
	next := *g.snapshot
	next.summary.Title = "second"
	next.summary.State = "archived"
	g.snapshot = &next
	if s.Title != "first" {
		t.Fatal("old summary mutated")
	}
	fresh, _, status := reader.Listing(1)
	if status != 200 || fresh.State != "archived" || fresh.Title != "second" {
		t.Fatal(fresh, status)
	}
	for _, now := range []domain.Time{100, 1} {
		if s, p, status := reader.Listing(now); status != 410 || s != nil || p != nil {
			t.Fatal("expired listing returned", s, status)
		}
	}
	if lease.Check(1) == nil {
		t.Fatal("expired listing lease survived")
	}
}
