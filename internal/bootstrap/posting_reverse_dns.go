// 接続元IPのDNS観測を投稿原本へ固定する。ネットワーク処理は板ワーカーの外でのみ実行する。
package bootstrap

import (
	"context"
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// observePostingReverseDNS は既存の有界DNS照会を共有し、投稿時の結果だけを保存用にコピーする。
// 未照会・待機上限・対象外のIPでは欠測を維持し、DNSの失敗だけで投稿を拒否しない。
func (r *Repository) observePostingReverseDNS(ctx context.Context, observation evidence.HTTPObservation) (evidence.HTTPObservation, error) {
	ip, err := netip.ParseAddr(observation.Resolved.IP)
	if err != nil {
		return evidence.HTTPObservation{}, evidence.ErrHTTPObservation
	}
	r.resolveNetworkHost(ctx, ip, true)
	value, ok := r.networkHosts.Observation(ip)
	if !ok {
		return observation, nil
	}
	return observation.WithReverseDNS(evidence.ReverseDNSObservation{Names: value.Names, ConfirmedName: value.ConfirmedName, Status: string(value.Status), ObservedAt: domain.Time(value.ObservedAt.UnixNano()), Resolver: value.Resolver})
}
