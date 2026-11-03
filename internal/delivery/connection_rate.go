// TLS前の新規接続頻度を有界にし、接続を作り直す攻撃の暗号処理を抑える。
package delivery

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"
)

const connectionRateSources = 4096

// ConnectionRate は新規TCP接続の毎秒上限と瞬間枠。稼働済み接続の要求数には適用しない。
type ConnectionRate struct {
	GlobalRate, GlobalBurst int
	SourceRate, SourceBurst int
}

// PublicConnectionRate は直結公開口と公開中継で使うTLS前の頻度上限を返す。
// 同じIPv4またはIPv6 /64を共有する利用者は同一の枠を消費する。
func PublicConnectionRate() ConnectionRate {
	return ConnectionRate{GlobalRate: 256, GlobalBurst: 512, SourceRate: 16, SourceBurst: 64}
}

type connectionBucket struct {
	tokens float64
	at     time.Time
}

// refilled は成功時にだけ保存する補充候補を返し、拒否の反復で期限を延ばさない。
func (b connectionBucket) refilled(now time.Time, rate, burst int) connectionBucket {
	if b.at.IsZero() {
		return connectionBucket{tokens: float64(burst), at: now}
	}
	if now.After(b.at) {
		b.tokens = math.Min(float64(burst), b.tokens+now.Sub(b.at).Seconds()*float64(rate))
		b.at = now
	}
	return b
}

type connectionRateGuard struct {
	mu      sync.Mutex
	policy  ConnectionRate
	global  connectionBucket
	sources map[netip.Prefix]connectionBucket
	sweep   time.Time
}

func newConnectionRateGuard(policy ConnectionRate) *connectionRateGuard {
	return &connectionRateGuard{policy: policy, sources: make(map[netip.Prefix]connectionBucket)}
}

// allow は全体と回線の枠を同時に消費する。拒否した新規回線は記憶しない。
func (g *connectionRateGuard) allow(source netip.Prefix, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.policy
	if now.Before(g.global.at) {
		now = g.global.at
	}
	global := g.global.refilled(now, p.GlobalRate, p.GlobalBurst)
	if global.tokens < 1 {
		return false
	}
	g.expire(now)
	prior, exists := g.sources[source]
	if !exists && len(g.sources) >= connectionRateSources {
		return false
	}
	client := prior.refilled(now, p.SourceRate, p.SourceBurst)
	if client.tokens < 1 {
		return false
	}
	global.tokens--
	client.tokens--
	g.global = global
	g.sources[source] = client
	return true
}

// expire は要求到着時に最大毎秒一回、全瞬間枠が戻った回線を除去する。専用タイマーは持たない。
func (g *connectionRateGuard) expire(now time.Time) {
	if now.Before(g.sweep) {
		return
	}
	g.sweep = now.Add(time.Second)
	for key, value := range g.sources {
		if value.refilled(now, g.policy.SourceRate, g.policy.SourceBurst).tokens >= float64(g.policy.SourceBurst) {
			delete(g.sources, key)
		}
	}
}

type connectionRateListener struct {
	net.Listener
	guard *connectionRateGuard
}

// LimitConnectionRate はaccept直後、TLS・HTTP読出し前に超過接続を閉じる。
// 同時接続枠のlistenerを内側に置き、その枠で拒否した接続には頻度枠を使わない。
// 認証済み中継から保存側への集約接続には適用しない。
func LimitConnectionRate(inner net.Listener, p ConnectionRate) (net.Listener, error) {
	if inner == nil || p.GlobalRate < 1 || p.GlobalBurst < 1 || p.SourceRate < 1 || p.SourceBurst < 1 || p.SourceRate > p.GlobalRate || p.SourceBurst > p.GlobalBurst {
		return nil, errors.New("invalid connection rate limits")
	}
	return &connectionRateListener{Listener: inner, guard: newConnectionRateGuard(p)}, nil
}

// Accept は超過接続を待機させず閉じ、稼働済み接続の寿命・keep-aliveには介入しない。
func (l *connectionRateListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		source, err := connectionSource(conn.RemoteAddr())
		if err == nil && l.guard.allow(source, time.Now()) {
			return conn, nil
		}
		_ = conn.Close()
	}
}
