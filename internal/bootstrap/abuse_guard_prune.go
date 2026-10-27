// 一括処理内の不変な公開状態を照合し、同じ検出履歴の全走査を繰り返さない。
package bootstrap

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
)

// guardPruneCache は現在の所有列だけで使う。時刻の境界と状態identityを毎回再確認する。
// 他板の履歴は従来通り可視とし、global履歴の最短600秒期限は共有して監視する。
type guardPruneCache struct {
	until  domain.Time
	states map[uint64]app.AbuseVisibility
}

func (b *postingBoard) guardThreadVisibility(key uint64, now domain.Time) app.AbuseVisibility {
	if p := b.threads[key]; p != nil {
		return p.AbuseVisibility(now)
	}
	return app.AbuseVisibility{}
}

// valid は投稿確定・削除・公開停止・期限到達による状態変更を一括処理中も検出する。
func (c *guardPruneCache) valid(b *postingBoard, key uint64, now domain.Time) bool {
	if c == nil || now >= c.until {
		return false
	}
	if _, known := c.states[key]; !known {
		return false
	}
	for key, state := range c.states {
		if state != b.guardThreadVisibility(key, now) {
			return false
		}
	}
	return true
}

// pruneGuardCandidate はguard mutexと板所有列を保持したまま使う。
// 検出件数・類似度判定は毎要求実行し、公開状態が不変の時だけ履歴の掃除を共有する。
func (b *postingBoard) pruneGuardCandidate(key uint64, now domain.Time) {
	group := b.group
	if group == nil {
		b.guard.prune(now, b.guardVisibility(now))
		return
	}
	if group.guardPruning.valid(b, key, now) {
		return
	}
	cache := &guardPruneCache{states: map[uint64]app.AbuseVisibility{}}
	visible := func(owner domain.ID, key uint64, number uint32) bool {
		if owner != b.owner {
			return true
		}
		state, known := cache.states[key]
		if !known {
			state = b.guardThreadVisibility(key, now)
			cache.states[key] = state
		}
		return state.Visible(number)
	}
	cache.until = b.guard.prune(now, visible)
	cache.states[key] = b.guardThreadVisibility(key, now)
	group.guardPruning = cache
}
