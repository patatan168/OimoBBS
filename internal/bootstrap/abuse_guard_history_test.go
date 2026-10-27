// 履歴を有界な配列の窓で保持し、先頭を除いた参照と未確定件数を正しく更新する。
package bootstrap

import (
	"oimobbs/internal/domain"
	"testing"
)

func TestGuardHistoryWindowBoundAndClear(t *testing.T) {
	g := &abuseGuard{settings: defaultAbuseGuard()}
	owner := domain.NewID()
	at := domain.Time(1000e9)
	for i := 1; i <= guardHistoryLimit*3; i++ {
		old := g.entries
		e := guardTestEntry(owner, 1, "本文", i, at+domain.Time(i))
		g.remember(e)
		want := min(i, guardHistoryLimit)
		if len(g.entries) != want || cap(g.entries) > guardHistoryLimit*2 || int(g.entries[0].number) != i-want+1 || int(g.entries[len(g.entries)-1].number) != i {
			t.Fatal("history window", i, len(g.entries), cap(g.entries))
		}
		if len(old) == guardHistoryLimit && cap(old) > len(old) && old[0].id != (domain.ID{}) {
			t.Fatal("removed cell retained identifiers/signature")
		}
	}
	if g.pending != 0 {
		t.Fatal(g.pending)
	}
}

func TestGuardPendingCountSettlementAndExpiry(t *testing.T) {
	g := &abuseGuard{settings: defaultAbuseGuard()}
	g.settings.Similar.Mode = "off"
	g.settings.Flood.Mode = "off"
	owner := domain.NewID()
	at := domain.Time(1000e9)
	first := guardTestEntry(owner, 1, "本文", 1, at)
	first.pending = true
	g.remember(first)
	g.settle(first.id, true)
	g.settle(first.id, true)
	if g.pending != 0 {
		t.Fatal("duplicate settlement decremented count")
	}
	ids := make([]domain.ID, 128)
	for i := range ids {
		e := guardTestEntry(owner, 1, "未確定", i+2, at)
		e.pending = true
		ids[i] = e.id
		g.remember(e)
	}
	if err := g.check(guardTestEntry(owner, 1, "次", 130, at)); err != ErrPostingCapacity || g.pending != 128 {
		t.Fatal("pending limit", err, g.pending)
	}
	g.settle(ids[0], false)
	if err := g.check(guardTestEntry(owner, 1, "次", 130, at)); err != nil || g.pending != 127 {
		t.Fatal("cancellation not released", err, g.pending)
	}
	g.prune(at+guardHistorySeconds*1e9, nil)
	if g.pending != 0 || len(g.entries) != 0 {
		t.Fatal("expiry retained pending count")
	}
	g.settle(ids[1], false)
	if g.pending != 0 {
		t.Fatal("expired candidate double released")
	}
}
