// 同じ一括処理でも履歴期限・新キー・明示的掃除の境界を省略しないことを検査する。
package bootstrap

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"testing"
)

func TestGuardPruneCacheBoundaries(t *testing.T) {
	owner, other := domain.NewID(), domain.NewID()
	now := domain.Time(1000e9)
	b := &postingBoard{owner: owner, threads: map[uint64]*app.PostingLog{}, guard: &abuseGuard{settings: defaultAbuseGuard()}, group: &postingGroup{}}
	b.guard.entries = []guardEntry{{board: other, thread: 1, number: 1, at: now - 599e9}}
	b.pruneGuardCandidate(1, now)
	cache := b.group.guardPruning
	if cache == nil || !cache.valid(b, 1, now) || cache.until != now+1e9 {
		t.Fatal("wrong first boundary", cache)
	}
	b.pruneGuardCandidate(1, now+1)
	if b.group.guardPruning != cache {
		t.Fatal("unchanged snapshot rescanned")
	}
	if cache.valid(b, 2, now) || cache.valid(b, 1, now+1e9) {
		t.Fatal("new key/expiry not invalidated")
	}
	b.pruneGuardCandidate(1, now+1e9)
	if len(b.guard.entries) != 0 {
		t.Fatal("expired history retained")
	}
	b.pruneGuard()
	if b.group.guardPruning != nil {
		t.Fatal("explicit removal cache survived")
	}
}
