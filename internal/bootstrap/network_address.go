// 外部データ取得先を通常の公開IPに制限し、共有・変換・試験用ネットワークへの接続を防ぐ。
package bootstrap

import (
	"context"
	"net"
	"net/netip"
)

// 分類表の取得には特殊用途の宛先を使わない。IPv6の変換・トンネル経路も許可しない。
var networkSpecialPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var networkIPv6Unicast = netip.MustParsePrefix("2000::/3")

// publicNetworkAddress は直接接続できる公開IPだけを許す。mapped IPv4にも同じIPv4制限を適用する。
// IsGlobalUnicastだけでは共有・文書用・予約アドレスを除外できないため、用途も検査する。
func publicNetworkAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Is6() && !networkIPv6Unicast.Contains(ip) {
		return false
	}
	for _, prefix := range networkSpecialPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// dialNetworkAddress は全DNS回答を検査後、そのIPへ直接接続して検査後の再解決を防ぐ。
// lookupとdialは同じContextを使う。公開・内部IPの混在は一つも接続せず拒否する。
func dialNetworkAddress(ctx context.Context, network, address string, lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, errNetworkFetch
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errNetworkFetch
	}
	for _, ip := range ips {
		if !publicNetworkAddress(ip) {
			return nil, errNetworkFetch
		}
	}
	for _, ip := range ips {
		var conn net.Conn
		conn, err = dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}
