// 同期タイマーを作らず、メモリ上限付きの頻度制限と処理枠を要求単位で管理する。
package waf

import (
	"math"
	"net/http"
	"net/netip"
	"sync"
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
	active           int
	last             time.Time
}

// TrafficStats はIPを含まない起動後の集計。稼働数は終了時に解放される。
type TrafficStats struct {
	Clients      int    `json:"clients"`
	Active       int    `json:"active"`
	SearchActive int    `json:"search_active"`
	RateLimited  uint64 `json:"rate_limited"`
	Overloaded   uint64 `json:"overloaded"`
}

// TrafficDecision は拒否時のHTTP状態と、最短の再試行待ち秒数。Status=0は通過。
type TrafficDecision struct{ Status, RetryAfter int }

// TrafficGuard は最大4096主体の枠を保持する。使用開始後に値をコピーしない。
type TrafficGuard struct {
	mu             sync.Mutex
	settings       TrafficSettings
	global, search trafficBucket
	clients        map[netip.Prefix]*trafficClient
	sweep          time.Time
	stats          TrafficStats
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
	g.settings = settings
}

// Acquire は枠を一度だけ取得する。拒否ではトークンを消費せず、IP停止期限も作らない。
// 通過時のreleaseは必ず呼ぶこと。複数回呼んでも一回分だけ解放する。
func (g *TrafficGuard) Acquire(ip netip.Addr, search bool, now time.Time) (func(), TrafficDecision) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.settings
	if !s.Enabled {
		return func() {}, TrafficDecision{}
	}
	if !ip.IsValid() || ip.Zone() != "" {
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
	if decision := g.globalLimit(search); decision.Status != 0 {
		return nil, g.reject(decision.Status, decision.RetryAfter)
	}
	client := g.clients[key]
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
	decision := g.clientLimit(client, search)
	if decision.Status != 0 {
		return nil, g.reject(decision.Status, decision.RetryAfter)
	}
	g.global.tokens--
	client.requests.tokens--
	client.active++
	g.stats.Active++
	if search {
		g.search.tokens--
		client.search.tokens--
		g.stats.SearchActive++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			client.active--
			g.stats.Active--
			if search {
				g.stats.SearchActive--
			}
		})
	}, TrafficDecision{}
}

// globalLimit は回線の記憶より先に全体枠を確認し、拒否する新規回線を記憶しない。
func (g *TrafficGuard) globalLimit(search bool) TrafficDecision {
	s := g.settings
	if g.stats.Active >= s.GlobalConcurrent {
		return TrafficDecision{503, 1}
	}
	if g.global.tokens < 1 {
		return TrafficDecision{503, g.global.retry(s.GlobalRate)}
	}
	if search {
		if g.stats.SearchActive >= s.SearchConcurrent {
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
	if client.active >= s.ClientConcurrent {
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
		if client.active == 0 && now.Sub(client.last) >= trafficIdle {
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
	return stats
}
