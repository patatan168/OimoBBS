// 主体の和集合・取消・公開削除・期限・設定変更を、旧全履歴走査と照合する。
package bootstrap

import (
	"encoding/binary"
	"math/rand/v2"
	"oimobbs/internal/domain"
	"testing"
)

func referenceFloodCounts(g *abuseGuard, e guardEntry) (thread, subject, share int) {
	thread, subject, share = 1, 1, 1
	for _, old := range g.entries {
		if old.at <= e.at-domain.Time(g.settings.Flood.WindowSeconds)*1e9 || old.cap && g.settings.ExemptCaps {
			continue
		}
		same := old.ip == e.ip && e.ip != (domain.Hash{}) || old.token == e.token && e.token != (domain.Hash{})
		if same {
			subject++
		}
		if e.thread != 0 && old.board == e.board && old.thread == e.thread {
			thread++
			if same {
				share++
			}
		}
	}
	return
}
func assertFloodCounts(t testing.TB, g *abuseGuard, e guardEntry) {
	t.Helper()
	a, b, c := referenceFloodCounts(g, e)
	x, y, z := g.floodCounts(e)
	if a != x || b != y || c != z {
		t.Fatalf("counts: want %d/%d/%d got %d/%d/%d at %d", a, b, c, x, y, z, e.at)
	}
	if len(g.flood.rows) > guardHistoryLimit*2 || cap(g.flood.rows) > guardHistoryLimit*2 || g.flood.global.total > len(g.entries) {
		t.Fatal("unbounded flood index")
	}
}
func TestGuardFloodIndexMatchesFullHistory(t *testing.T) {
	g := &abuseGuard{settings: defaultAbuseGuard()}
	rng := rand.New(rand.NewPCG(17, 31))
	now := domain.Time(1000e9)
	for i := range 18000 {
		now += domain.Time(rng.IntN(200)) * 1e6
		if i%173 == 0 {
			g.settings.ExemptCaps = !g.settings.ExemptCaps
			g.settings.Flood.WindowSeconds = 1 + rng.IntN(600)
		}
		e := guardEntry{at: now, board: domain.ID{byte(rng.IntN(3) + 1)}, thread: uint64(rng.IntN(5)), ip: domain.Hash{byte(rng.IntN(10))}, token: domain.Hash{byte(rng.IntN(13))}, cap: rng.IntN(9) == 0, pending: i%3 == 0, number: uint32(i + 1)}
		binary.LittleEndian.PutUint64(e.id[:], uint64(i+1))
		assertFloodCounts(t, g, e)
		g.remember(e)
		if i%7 == 0 && len(g.entries) > 0 {
			index := rng.IntN(len(g.entries))
			g.settle(g.entries[index].id, rng.IntN(2) == 0)
		}
		if i%127 == 0 {
			g.prune(now, func(_ domain.ID, _ uint64, number uint32) bool { return number%11 != 0 })
		}
		assertFloodCounts(t, g, e)
	}
	now += 1000e9
	assertFloodCounts(t, g, guardEntry{at: now, ip: domain.Hash{1}})
	g.remember(guardEntry{at: now, ip: domain.Hash{1}})
	assertFloodCounts(t, g, guardEntry{at: now, ip: domain.Hash{1}})
	// 復旧などで逆順の内部挿入をした場合も再構築して完全な件数へ戻す。
	g.remember(guardEntry{at: now - 1, ip: domain.Hash{1}})
	assertFloodCounts(t, g, guardEntry{at: now, ip: domain.Hash{1}})
}

func TestGuardFloodIndexSubjectUnionAndCreateKey(t *testing.T) {
	g := &abuseGuard{settings: defaultAbuseGuard()}
	now := domain.Time(1000e9)
	e := guardEntry{id: domain.ID{1}, board: domain.ID{2}, at: now, ip: domain.Hash{3}, token: domain.Hash{4}, pending: true}
	g.remember(e)
	query := e
	query.thread = 9
	assertFloodCounts(t, g, query)
	board := &postingBoard{guard: g}
	board.updateGuardCandidate(e.id, 9, 1)
	assertFloodCounts(t, g, query)
	index := g.flood
	board.updateGuardCandidate(e.id, 9, 2)
	if g.flood != index {
		t.Fatal("ordinary reply discarded the count index")
	}
	a, b, c := g.floodCounts(query)
	if a != 2 || b != 2 || c != 2 {
		t.Fatal("union counted twice", a, b, c)
	}
	g.settle(e.id, false)
	g.settle(e.id, false)
	assertFloodCounts(t, g, query)
}
