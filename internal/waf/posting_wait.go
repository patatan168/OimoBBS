// 投稿の全体同時枠だけを短時間・有限個待ち、頻度と同一回線の超過は即時に拒否する。
package waf

import (
	"context"
	"net/http"
	"net/netip"
	"time"
)

const postingWaitLimit = 32
const postingWaitTimeout = 500 * time.Millisecond

// AcquirePosting は同時枠の一時的な競合だけを最大500ms待つ。実行上限・頻度は緩和しない。
// 待機は全体32件または実行枠数の小さい方。回線別制限ON時はIPv4/IPv6の/64ごとに1件まで。
// 取消・期限・設定変更でも待機を解放し、取得できたreleaseは必ず一度呼ぶこと。
func (g *TrafficGuard) AcquirePosting(ctx context.Context, ip netip.Addr, now time.Time) (func(), TrafficDecision) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var cleanup func()
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()
	started, initial := time.Now(), now
	for {
		if ctx.Err() != nil {
			return nil, g.rejectWork(0, TrafficDecision{http.StatusServiceUnavailable, 1})
		}
		release, decision, blocked := g.acquireOperation(ip, Posting, now, true)
		if !blocked {
			return release, decision
		}
		if cleanup == nil {
			key, ok := g.beginPostingWait(ip)
			if !ok {
				return nil, g.rejectWork(0, decision)
			}
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, postingWaitTimeout)
			cleanup = func() { cancel(); g.endPostingWait(key) }
		}
		// 解放が最初の満杯判定と待機登録の間に起きても、通知を取り逃さない。
		if g.work[0].active.Load() < int64(g.workLimits[0].globalConcurrent) {
			continue
		}
		changed := g.postingChanged
		g.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-changed:
		}
		g.mu.Lock()
		now = initial.Add(time.Since(started))
	}
}

// beginPostingWait は検証済み回線の待機を上限内で登録する。guardの排他を所有する。
func (g *TrafficGuard) beginPostingWait(ip netip.Addr) (netip.Prefix, bool) {
	bits := 64
	if ip.Unmap().Is4() {
		bits = 32
	}
	key := netip.PrefixFrom(ip.Unmap(), bits).Masked()
	if g.settings.ClientEnabled && g.postingWaiters[key] != 0 || int(g.postingWaiting.Load()) >= min(postingWaitLimit, g.workLimits[0].globalConcurrent) {
		return key, false
	}
	if g.postingWaiters == nil {
		g.postingWaiters = make(map[netip.Prefix]int)
	}
	if g.postingChanged == nil {
		g.postingChanged = make(chan struct{})
	}
	g.postingWaiters[key]++
	g.postingWaiting.Add(1)
	g.workStats[0].Queued++
	return key, true
}

// endPostingWait は全ての終了経路で待機登録を外す。guardの排他を所有する。
func (g *TrafficGuard) endPostingWait(key netip.Prefix) {
	g.postingWaiters[key]--
	if g.postingWaiters[key] == 0 {
		delete(g.postingWaiters, key)
	}
	g.postingWaiting.Add(-1)
	if len(g.postingWaiters) == 0 {
		g.postingChanged = nil
	}
}

// postingCanWait は全体同時枠だけの競合か調べ、新規IPの状態やトークンを増減しない。
// 同一回線の枠超過・頻度超過、全体の頻度超過には待機を与えない。
func (g *TrafficGuard) postingCanWait(key netip.Prefix, now time.Time) bool {
	limit, state := g.workLimits[0], &g.work[0]
	if state.bucket.tokens < 1 {
		return false
	}
	if !g.settings.ClientEnabled {
		return true
	}
	c := g.clients[key]
	if c == nil {
		return true
	}
	c.requests.refill(now, g.settings.ClientRate, g.settings.ClientBurst)
	c.search.refill(now, g.settings.SearchRate, g.settings.SearchBurst)
	if g.clientLimit(c, false).Status != 0 {
		return false
	}
	if c.work == nil {
		return true
	}
	c.work[0].bucket.refill(now, limit.clientRate, limit.clientBurst)
	return c.work[0].active.Load() < int64(limit.clientConcurrent) && c.work[0].bucket.tokens >= 1
}

// notifyPostingLocked は枠解放・設定変更を通知する。待機がない通常経路では呼ばない。
func (g *TrafficGuard) notifyPostingLocked() {
	if g.postingChanged != nil {
		close(g.postingChanged)
		g.postingChanged = make(chan struct{})
	}
}
