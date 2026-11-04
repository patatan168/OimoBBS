// QUICの暗号処理前に、新規接続頻度と接続の全体・回線別枠を予約する。
package delivery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// QUICAdmission はIPv4単位・IPv6 /64単位でUDP接続の寿命を数える。
// TLS失敗も接続contextの取消で枠を返す。TCPとは独立した有限枠を使う。
type QUICAdmission struct {
	mu                      sync.Mutex
	total, limit, perSource int
	sources                 map[netip.Prefix]int
	rate                    *connectionRateGuard
	unvalidated             *connectionRateGuard
}

// NewQUICAdmission は待機しないQUIC接続枠を作る。
func NewQUICAdmission(limit, perSource int) (*QUICAdmission, error) {
	if limit < 1 || perSource < 1 || perSource > limit {
		return nil, errors.New("invalid QUIC admission limits")
	}
	p := PublicConnectionRate()
	// Retry往復と再送に余裕を持たせ、TLS接続枠とは独立して未検証入力を制限する。
	initial := ConnectionRate{GlobalRate: 4 * p.GlobalRate, GlobalBurst: 4 * p.GlobalBurst, SourceRate: 4 * p.SourceRate, SourceBurst: 4 * p.SourceBurst}
	return &QUICAdmission{limit: limit, perSource: perSource, sources: make(map[netip.Prefix]int), rate: newConnectionRateGuard(p), unvalidated: newConnectionRateGuard(initial)}, nil
}

// AllowUnvalidated はRetry生成・token検証・version応答より前に実送信元の頻度枠を消費する。
// 未検証IPの記録は4096回線まで。既存接続のpacketやTLS接続枠には使わない。
func (g *QUICAdmission) AllowUnvalidated(remote net.Addr) bool {
	source, err := connectionSource(remote)
	return err == nil && g.unvalidated.allow(source, time.Now())
}

// Admit は検証済みの実接続元を予約し、接続の取消で一度だけ解放する。
func (g *QUICAdmission) Admit(ctx context.Context, remote net.Addr) error {
	source, err := connectionSource(remote)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if g.total >= g.limit || g.sources[source] >= g.perSource || !g.rate.allow(source, time.Now()) {
		return errors.New("QUIC connection admission exhausted")
	}
	g.total++
	g.sources[source]++
	context.AfterFunc(ctx, func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.total--
		g.sources[source]--
		if g.sources[source] == 0 {
			delete(g.sources, source)
		}
	})
	return nil
}
