// 投稿確認/管理照会のサービスDNSを所有ワーカー外で準備する。
package bootstrap

import (
	"context"
	"net/netip"
	"strings"
	"time"
)

// resolveNetworkHost は初回の待機を750ms以内にする。逆引き確認を要求する場合は分類上書きでも照会する。
func (r *Repository) resolveNetworkHost(ctx context.Context, ip netip.Addr, requireReverse ...bool) {
	if r.networkHosts == nil {
		return
	}
	classifier := r.liveNetworks.Load()
	if classifier != nil && !(len(requireReverse) > 0 && requireReverse[0]) {
		if _, ok := classifier.Overrides.Match(ip); ok {
			return
		}
		access := classifier.ClassifyAccess(ip)
		if access.VPN == "vpn" || access.Country == "foreign" {
			return
		}
	}
	wait, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	r.networkHosts.Resolve(wait, ip)
}

// probeNetworkContext はHTTP側の取消に追従してサービス候補を準備し、共通の分類を返す。
func (r *Repository) probeNetworkContext(ctx context.Context, raw string) (networkProbe, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err == nil {
		r.resolveNetworkHost(ctx, ip, true)
	}
	probe, err := r.probeNetwork(raw)
	if err == nil {
		probe.ReverseResolved = r.networkHosts.ReverseResolved(ip)
	}
	return probe, err
}
