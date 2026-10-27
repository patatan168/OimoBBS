// 署名の消去済みprefixを省略しても、古い未確定候補の後追い確定と取消が署名を復活させない。
package bootstrap

import (
	"oimobbs/internal/domain"
	"reflect"
	"testing"
)

func TestGuardSignatureFloorKeepsLatestCommitted(t *testing.T) {
	g := &abuseGuard{settings: defaultAbuseGuard()}
	reference := &abuseGuard{settings: defaultAbuseGuard()}
	owner := domain.NewID()
	at := domain.Time(1000e9)
	check := func() {
		t.Helper()
		if !reflect.DeepEqual(g.entries, reference.entries) {
			t.Fatal("optimized trimming differs from full scan")
		}
		committed := 0
		for i := len(g.entries) - 1; i >= 0; i-- {
			e := g.entries[i]
			if e.pending {
				continue
			}
			committed++
			if committed > 128 && e.signature.exact != (domain.Hash{}) {
				t.Fatal("old committed signature retained", i)
			}
		}
	}
	var pending []domain.ID
	for i := 0; i < 600; i++ {
		e := guardTestEntry(owner, 1, "署名のある本文", i+1, at+domain.Time(i))
		e.pending = i%3 == 0
		if e.pending {
			pending = append(pending, e.id)
		}
		g.remember(e)
		reference.signatureFloor = 0
		reference.remember(e)
		check()
	}
	// 128件より古いpendingを新しい順に確定/取消し、すでに消去したprefixを越える。
	for i := len(pending) - 1; i >= 0; i-- {
		g.settle(pending[i], i%2 == 0)
		reference.signatureFloor = 0
		reference.settle(pending[i], i%2 == 0)
		check()
	}
	g.prune(at+1000, func(_ domain.ID, _ uint64, number uint32) bool { return number%5 != 0 })
	reference.signatureFloor = 0
	reference.prune(at+1000, func(_ domain.ID, _ uint64, number uint32) bool { return number%5 != 0 })
	check()
	for i := 600; i < 750; i++ {
		e := guardTestEntry(owner, 1, "新しい署名", i+1, at+domain.Time(i))
		g.remember(e)
		reference.signatureFloor = 0
		reference.remember(e)
		check()
	}
}

// 最新側の削除で保持境界が古いpendingへ戻った後も、確定時の署名を過剰に消さない。
func TestGuardSignatureFloorPruneRetainsNewlyRecentPending(t *testing.T) {
	g := &abuseGuard{settings: defaultAbuseGuard()}
	ref := &abuseGuard{settings: defaultAbuseGuard()}
	owner := domain.ID{1}
	var pending domain.ID
	for i := range 400 {
		e := guardTestEntry(owner, 1, "古い未確定署名も比較する本文", i+1, domain.Time(1000e9)+domain.Time(i))
		if i == 240 {
			e.pending = true
			pending = e.id
		}
		g.remember(e)
		ref.signatureFloor = 0
		ref.remember(e)
	}
	visible := func(_ domain.ID, _ uint64, number uint32) bool { return number <= 270 }
	g.prune(domain.Time(1001e9), visible)
	ref.signatureFloor = 0
	ref.prune(domain.Time(1001e9), visible)
	g.settle(pending, true)
	ref.signatureFloor = 0
	ref.settle(pending, true)
	if !reflect.DeepEqual(g.entries, ref.entries) {
		t.Fatal("pruned pending differed from full scan")
	}
	for _, e := range g.entries {
		if e.id == pending && e.signature.exact == (domain.Hash{}) {
			t.Fatal("recent committed signature lost after deletion")
		}
	}
}
