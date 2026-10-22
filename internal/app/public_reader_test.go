// 保存列外の公開候補について、停止・期限・時計逆行と旧本文の解放を確認する。
package app

import (
	"oimobbs/internal/domain"
	"testing"
)

func TestPublicReaderRevocationAndExpiry(t *testing.T) {
	g := &publicationGate{leases: map[*PublicLease]func(){}}
	p := &PostingLog{gate: g}
	reader := p.PublicReader()
	if s, status := reader.Snapshot(1); s != nil || status != 404 {
		t.Fatal(status)
	}
	g.snapshot = &PostingSnapshot{gate: g, DAT: []byte("confirmed\n"), Expires: 100}
	s, status := reader.Snapshot(1)
	if status != 200 || string(s.DAT) != "confirmed\n" {
		t.Fatal(status)
	}
	lease, err := s.AcquirePublic(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	p.BlockPublic(true)
	if s, status := reader.Snapshot(1); s != nil || status != 503 || g.snapshot != nil {
		t.Fatal(status)
	}
	if lease.Check(1) == nil {
		t.Fatal("old lease survived block")
	}
	g.mu.Lock()
	g.blocked = false
	g.snapshot = &PostingSnapshot{gate: g, epoch: g.epoch, DAT: []byte("new\n"), Expires: 100}
	g.mu.Unlock()
	fresh, status := reader.Snapshot(1)
	if status != 200 {
		t.Fatal(status)
	}
	revoked := false
	active, err := fresh.AcquirePublic(1, func() { revoked = true })
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	for _, now := range []int64{100, 1} {
		if s, status := reader.Snapshot(domain.Time(now)); s != nil || status != 410 || g.snapshot != nil {
			t.Fatal(status)
		}
	}
	if !revoked {
		t.Fatal("expiry did not cancel active sender")
	}
}
