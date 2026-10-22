// 高負荷の処理だけに追加する頻度・同時処理枠を、通常枠と同じロック内で管理する。
package waf

import "time"

// Operation は枠を共有する処理の種類。公開・管理の振り分けはHTTP受付側で行う。
type Operation uint8

const (
	Ordinary Operation = iota
	Search
	Posting
	Reports
	Authentication
	operationEnd
)

const workCount = int(operationEnd - Posting)

type workState struct {
	bucket trafficBucket
	active int
}

// WorkStats は処理別の稼働数と拒否件数。IPや要求内容を含めない。
type WorkStats struct {
	Active      int    `json:"active"`
	RateLimited uint64 `json:"rate_limited"`
	Overloaded  uint64 `json:"overloaded"`
}

type workLimit struct {
	clientRate, clientBurst, clientConcurrent int
	globalRate, globalBurst, globalConcurrent int
}

// workLimits は投稿設定と固定の管理保護枠を、通常枠を超えない上限へ切り詰める。
func workLimits(s TrafficSettings) [workCount]workLimit {
	caps := [workCount]workLimit{
		{s.Posting.ClientRate, s.Posting.ClientBurst, s.Posting.ClientConcurrent, s.Posting.GlobalRate, s.Posting.GlobalBurst, s.Posting.GlobalConcurrent}, // 専ブラ・Web共通。
		{2, 6, 2, 8, 16, 4}, // 削除依頼・秘密付き照会。ディスクとサイトmutexを保護する。
		{1, 3, 1, 4, 8, 2},  // パスワード照合。既存の2workerより先に拒否する。
	}
	for i := range caps {
		v := &caps[i]
		v.clientRate = min(v.clientRate, s.ClientRate)
		v.clientBurst = min(v.clientBurst, s.ClientBurst)
		v.clientConcurrent = min(v.clientConcurrent, s.ClientConcurrent)
		v.globalRate = min(v.globalRate, s.GlobalRate)
		v.globalBurst = min(v.globalBurst, s.GlobalBurst)
		v.globalConcurrent = min(v.globalConcurrent, s.GlobalConcurrent)
	}
	return caps
}

// configureWork は設定切替時も補充速度・消費量・実行数を引き継ぐ。guardのmutexを所有する。
func (g *TrafficGuard) configureWork(s TrafficSettings, now time.Time) {
	limits := workLimits(s)
	for i, next := range limits {
		old := g.workLimits[i]
		if old.globalRate == 0 {
			old = next
		}
		state := &g.work[i]
		state.bucket.refill(now, old.globalRate, old.globalBurst)
		state.bucket.tokens = min(state.bucket.tokens, float64(next.globalBurst))
		for _, c := range g.clients {
			if c.work == nil {
				continue
			}
			state := &c.work[i]
			state.bucket.refill(now, old.clientRate, old.clientBurst)
			state.bucket.tokens = min(state.bucket.tokens, float64(next.clientBurst))
		}
	}
	g.workLimits = limits
}

// globalWorkLimit は新規回線の記憶・本文受信より先に処理全体の枠を検査する。
func (g *TrafficGuard) globalWorkLimit(i int, now time.Time) TrafficDecision {
	s, state := g.workLimits[i], &g.work[i]
	state.bucket.refill(now, s.globalRate, s.globalBurst)
	if state.active >= s.globalConcurrent {
		return TrafficDecision{503, 1}
	}
	if state.bucket.tokens < 1 {
		return TrafficDecision{503, state.bucket.retry(s.globalRate)}
	}
	return TrafficDecision{}
}

// clientWorkLimit は処理を初めて利用する回線にだけ追加枠を確保する。
func (g *TrafficGuard) clientWorkLimit(c *trafficClient, i int, now time.Time) TrafficDecision {
	if c.work == nil {
		c.work = new([workCount]workState)
	}
	s, state := g.workLimits[i], &c.work[i]
	state.bucket.refill(now, s.clientRate, s.clientBurst)
	if state.active >= s.clientConcurrent {
		return TrafficDecision{429, 1}
	}
	if state.bucket.tokens < 1 {
		return TrafficDecision{429, state.bucket.retry(s.clientRate)}
	}
	return TrafficDecision{}
}

func (g *TrafficGuard) rejectWork(i int, d TrafficDecision) TrafficDecision {
	if d.Status == 429 {
		g.workStats[i].RateLimited++
	} else {
		g.workStats[i].Overloaded++
	}
	return g.reject(d.Status, d.RetryAfter)
}
