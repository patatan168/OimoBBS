// 同期タイマーを作らず、メモリ上限付きの頻度制限と処理枠を要求単位で管理する。
package waf

import (
	"math"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const trafficClientLimit = 4096
const trafficIdle = time.Minute * 2

type trafficBucket struct {
	tokens float64
	last   time.Time
}

func (b *trafficBucket) refill(now time.Time, rate, burst int) {
	if b.last.IsZero() {
		b.tokens = float64(burst)
		b.last = now
		return
	}
	if now.After(b.last) {
		b.tokens = math.Min(float64(burst), b.tokens+now.Sub(b.last).Seconds()*float64(rate))
		b.last = now
	}
}
func (b *trafficBucket) retry(rate int) int {
	return max(1, int(math.Ceil((1-b.tokens)/float64(rate))))
}

type trafficClient struct {
	requests, search trafficBucket
	active           atomic.Int64
	last             time.Time
	work             *[workCount]workState
}

// TrafficStats はIPを含まない起動後の集計。稼働数は終了時に解放される。
type TrafficStats struct {
	Clients        int       `json:"clients"`
	Active         int       `json:"active"`
	SearchActive   int       `json:"search_active"`
	RateLimited    uint64    `json:"rate_limited"`
	Overloaded     uint64    `json:"overloaded"`
	Posting        WorkStats `json:"posting"`
	Reports        WorkStats `json:"reports"`
	Authentication WorkStats `json:"authentication"`
}

// TrafficDecision は拒否時のHTTP状態と、最短の再試行待ち秒数。Status=0は通過。
type TrafficDecision struct{ Status, RetryAfter int }

// TrafficGuard は最大4096主体の枠を保持する。使用開始後に値をコピーしない。
type TrafficGuard struct {
	mu                   sync.Mutex
	active, searchActive atomic.Int64
	settings             TrafficSettings
	global, search       trafficBucket
	clients              map[netip.Prefix]*trafficClient
	sweep                time.Time
	stats                TrafficStats
	work                 [workCount]workState
	workLimits           [workCount]workLimit
	workStats            [workCount]WorkStats
}

// Configure は実行中の枠・消費済みトークンを維持して設定を交換する。不正設定はpanicする。
// 呼び出し元でValidを検査し、保存成功後にだけ実行する。
func (g *TrafficGuard) Configure(settings TrafficSettings, now time.Time) {
	if !settings.Valid() {
		panic("invalid traffic settings")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.clients == nil {
		g.clients = make(map[netip.Prefix]*trafficClient)
	} else {
		g.global.refill(now, g.settings.GlobalRate, g.settings.GlobalBurst)
		g.search.refill(now, g.settings.SearchGlobalRate, g.settings.SearchGlobalBurst)
		for _, client := range g.clients {
			client.requests.refill(now, g.settings.ClientRate, g.settings.ClientBurst)
			client.search.refill(now, g.settings.SearchRate, g.settings.SearchBurst)
			client.requests.tokens = math.Min(client.requests.tokens, float64(settings.ClientBurst))
			client.search.tokens = math.Min(client.search.tokens, float64(settings.SearchBurst))
		}
	}
	g.global.refill(now, settings.GlobalRate, settings.GlobalBurst)
	g.search.refill(now, settings.SearchGlobalRate, settings.SearchGlobalBurst)
	g.global.tokens = math.Min(g.global.tokens, float64(settings.GlobalBurst))
	g.search.tokens = math.Min(g.search.tokens, float64(settings.SearchGlobalBurst))
	g.configureWork(settings, now)
	g.settings = settings
}

// Acquire は枠を一度だけ取得する。拒否ではトークンを消費せず、IP停止期限も作らない。
// 通過時のreleaseは必ず呼ぶこと。複数回呼んでも一回分だけ解放する。
func (g *TrafficGuard) Acquire(ip netip.Addr, search bool, now time.Time) (func(), TrafficDecision) {
	op := Ordinary
	if search {
		op = Search
	}
	return g.AcquireOperation(ip, op, now)
}

// AcquireOperation は通常枠と処理別枠を同じロックで確保する。拒否時はどのトークンも消費しない。
// 通過時のreleaseは必ず呼ぶこと。不正な処理種別は503で拒否する。
func (g *TrafficGuard) AcquireOperation(ip netip.Addr, op Operation, now time.Time) (func(), TrafficDecision) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.settings
	if !s.Enabled {
		return func() {}, TrafficDecision{}
	}
	if !ip.IsValid() || ip.Zone() != "" || op >= operationEnd {
		return nil, g.reject(http.StatusServiceUnavailable, 1)
	}
	ip = ip.Unmap()
	bits := 64
	if ip.Is4() {
		bits = 32
	}
	key := netip.PrefixFrom(ip, bits).Masked()
	if now.Before(g.global.last) {
		// 時刻取得後に別goroutineが先にロックを得ても拒否しない。
		// 時計の巻戻りでは補充せず、最後の時刻まで固定する。
		now = g.global.last
	}
	g.expire(now)
	g.global.refill(now, s.GlobalRate, s.GlobalBurst)
	g.search.refill(now, s.SearchGlobalRate, s.SearchGlobalBurst)
	search := op == Search
	work := int(op) - int(Posting)
	if decision := g.globalLimit(search); decision.Status != 0 {
		return nil, g.reject(decision.Status, decision.RetryAfter)
	}
	if work >= 0 {
		if d := g.globalWorkLimit(work, now); d.Status != 0 {
			return nil, g.rejectWork(work, d)
		}
	}

	var client *trafficClient
	if s.ClientEnabled {
		client = g.clients[key]
		if client == nil {
			if len(g.clients) >= trafficClientLimit {
				return nil, g.reject(http.StatusServiceUnavailable, 1)
			}
			client = &trafficClient{}
			g.clients[key] = client
		}
		client.last = now
		client.requests.refill(now, s.ClientRate, s.ClientBurst)
		client.search.refill(now, s.SearchRate, s.SearchBurst)
		if decision := g.clientLimit(client, search); decision.Status != 0 {
			return nil, g.reject(decision.Status, decision.RetryAfter)
		}
		if work >= 0 {
			if d := g.clientWorkLimit(client, work, now); d.Status != 0 {
				return nil, g.rejectWork(work, d)
			}
		}
	}
	if work >= 0 {
		g.work[work].bucket.tokens--
		g.work[work].active.Add(1)
		if client != nil {
			client.work[work].bucket.tokens--
			client.work[work].active.Add(1)
		}
	}
	g.global.tokens--
	if client != nil {
		client.requests.tokens--
		client.active.Add(1)
	}
	g.active.Add(1)
	if search {
		g.search.tokens--
		if client != nil {
			client.search.tokens--
		}
		g.searchActive.Add(1)
	}
	// 解放は設定とトークンを変更しない。受付のmutexを待たず、重複呼出しだけをCASで防ぐ。
	var released atomic.Bool
	return func() {
		if !released.CompareAndSwap(false, true) {
			return
		}
		if work >= 0 {
			g.work[work].active.Add(-1)
			if client != nil {
				client.work[work].active.Add(-1)
			}
		}
		if search {
			g.searchActive.Add(-1)
		}
		if client != nil {
			client.active.Add(-1)
		}
		g.active.Add(-1)
	}, TrafficDecision{}
}

// globalLimit は回線の記憶より先に全体枠を確認し、拒否する新規回線を記憶しない。
func (g *TrafficGuard) globalLimit(search bool) TrafficDecision {
	s := g.settings
	if g.active.Load() >= int64(s.GlobalConcurrent) {
		return TrafficDecision{503, 1}
	}
	if g.global.tokens < 1 {
		return TrafficDecision{503, g.global.retry(s.GlobalRate)}
	}
	if search {
		if g.searchActive.Load() >= int64(s.SearchConcurrent) {
			return TrafficDecision{503, 1}
		}
		if g.search.tokens < 1 {
			return TrafficDecision{503, g.search.retry(s.SearchGlobalRate)}
		}
	}
	return TrafficDecision{}
}

// clientLimit は補充後の回線別枠を確認し、超過には429を返す。
func (g *TrafficGuard) clientLimit(client *trafficClient, search bool) TrafficDecision {
	s := g.settings
	if client.active.Load() >= int64(s.ClientConcurrent) {
		return TrafficDecision{429, 1}
	}
	if client.requests.tokens < 1 {
		return TrafficDecision{429, client.requests.retry(s.ClientRate)}
	}
	if search && client.search.tokens < 1 {
		return TrafficDecision{429, client.search.retry(s.SearchRate)}
	}
	return TrafficDecision{}
}

func (g *TrafficGuard) reject(status, retry int) TrafficDecision {
	if status == 429 {
		g.stats.RateLimited++
	} else {
		g.stats.Overloaded++
	}
	return TrafficDecision{status, retry}
}

// expire は10秒に一度だけ上限4096件を走査する。実行中または直近2分の主体は保持する。
func (g *TrafficGuard) expire(now time.Time) {
	if !g.sweep.IsZero() && now.Before(g.sweep) {
		return
	}
	for key, client := range g.clients {
		if client.active.Load() == 0 && now.Sub(client.last) >= trafficIdle {
			delete(g.clients, key)
		}
	}
	g.sweep = now.Add(10 * time.Second)
}

// Stats はIPを含まない集計のコピーを返す。
func (g *TrafficGuard) Stats() TrafficStats {
	g.mu.Lock()
	defer g.mu.Unlock()
	stats := g.stats
	stats.Clients = len(g.clients)
	stats.Active, stats.SearchActive = int(g.active.Load()), int(g.searchActive.Load())
	stats.Posting, stats.Reports, stats.Authentication = g.workStats[0], g.workStats[1], g.workStats[2]
	stats.Posting.Active, stats.Reports.Active, stats.Authentication.Active = int(g.work[0].active.Load()), int(g.work[1].active.Load()), int(g.work[2].active.Load())
	return stats
}
