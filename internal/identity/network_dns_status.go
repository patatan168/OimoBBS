// DNSの確定した不存在・不整合を一時障害から分離し、保存済み分類とは独立した表示材料を提供する。
package identity

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// HostDNSStatus はキャッシュ済みのDNS確認結果。未確認には取得待ち・期限切れ・一時障害を含む。
type HostDNSStatus string

const (
	HostDNSUnchecked HostDNSStatus = "unchecked"
	HostDNSConfirmed HostDNSStatus = "confirmed"
	HostDNSAbsent    HostDNSStatus = "absent"
	HostDNSMismatch  HostDNSStatus = "mismatch"
)

type hostInspection struct {
	class    NetworkClass
	hostname string
	reverse  bool
	status   HostDNSStatus
	names    []string
}

type hostLookupCandidate struct {
	name  string
	class NetworkClass
}

// DNSStatus は有効なキャッシュの状態だけを返す。外部照会は行わない。
func (c *HostCache) DNSStatus(ip netip.Addr) HostDNSStatus {
	value, ok := c.cached(ip)
	if !ok || value.status == "" {
		return HostDNSUnchecked
	}
	return value.status
}

// definitiveDNSAbsence はNXDOMAINなどの確定した不存在だけを採用する。
func definitiveDNSAbsence(err error) bool {
	var dns *net.DNSError
	return errors.As(err, &dns) && dns.IsNotFound && !dns.IsTimeout && !dns.IsTemporary
}

// inspectHost は有界のPTR→A/AAAA確認で、不正名・不一致と一時的な照会失敗を区別する。
func inspectHost(ctx context.Context, resolver HostResolver, ip netip.Addr) hostInspection {
	out := hostInspection{status: HostDNSUnchecked}
	names, err := resolver.LookupAddr(ctx, ip.String())
	if ctx.Err() != nil {
		return out
	}
	if err != nil {
		if definitiveDNSAbsence(err) {
			out.status = HostDNSAbsent
		}
		return out
	}
	if len(names) == 0 {
		out.status = HostDNSAbsent
		return out
	}
	if len(names) > 16 {
		return out
	}
	return inspectHostNames(ctx, resolver, ip, names)
}

// inspectHostNames は既知サービスから正引き確認し、未確定の照会が残る場合は不整合と断定しない。
func inspectHostNames(ctx context.Context, resolver HostResolver, ip netip.Addr, names []string) hostInspection {
	out := hostInspection{status: HostDNSUnchecked}
	candidates := hostLookupCandidates(ip, names)
	for _, candidate := range candidates {
		out.names = append(out.names, candidate.name)
	}
	slices.Sort(out.names)
	out.reverse = len(candidates) > 0
	uncertain := false
	for _, candidate := range candidates {
		status := inspectForward(ctx, resolver, ip, candidate.name)
		if status == HostDNSUnchecked {
			uncertain = true
			continue
		}
		if status != HostDNSConfirmed {
			continue
		}
		if out.hostname == "" {
			out.hostname = candidate.name
		}
		if candidate.class.CIDR != "" {
			out.hostname = candidate.name
			out.class = candidate.class
			out.status = HostDNSConfirmed
			return out
		}
	}
	if out.hostname != "" {
		out.status = HostDNSConfirmed
	} else if !uncertain && ctx.Err() == nil {
		out.status = HostDNSMismatch
	}
	return out
}

// hostLookupCandidates は正規化したPTRの重複を除き、既知名を先にする。各区分内の回答順は維持する。
// 分類は候補にすぎず、正引きが元IPに一致するまでinspectHostNamesで採用しない。
func hostLookupCandidates(ip netip.Addr, names []string) []hostLookupCandidate {
	seen := make(map[string]bool, len(names))
	var known, generic []hostLookupCandidate
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSuffix(raw, "."))
		if !validDNSHostname(name) || seen[name] {
			continue
		}
		seen[name] = true
		class, ok := serviceHostClass(ip, name)
		candidate := hostLookupCandidate{name: name, class: class}
		if ok {
			known = append(known, candidate)
		} else {
			generic = append(generic, candidate)
		}
	}
	return append(known, generic...)
}

// inspectForward は元IPと同じfamilyだけを正引きし、一致・確定不一致・一時障害を有界に確認する。
func inspectForward(ctx context.Context, resolver HostResolver, ip netip.Addr, name string) HostDNSStatus {
	if _, err := netip.ParseAddr(name); err == nil {
		return HostDNSMismatch
	}
	network := "ip6"
	if ip.Is4() {
		network = "ip4"
	}
	ips, err := resolver.LookupNetIP(ctx, network, name)
	if err != nil {
		if definitiveDNSAbsence(err) {
			return HostDNSMismatch
		}
		return HostDNSUnchecked
	}
	if len(ips) > 32 {
		return HostDNSUnchecked
	}
	for _, forward := range ips {
		if forward.Unmap() == ip {
			return HostDNSConfirmed
		}
	}
	return HostDNSMismatch
}

// serviceHostClass はサービス別の分類候補を返す。正引き一致の確認は呼出元の責務。
func serviceHostClass(ip netip.Addr, name string) (NetworkClass, bool) {
	for i, pattern := range hostPatterns {
		if pattern.MatchString(name) {
			rule := hostRules[i]
			return NetworkClass{CIDR: netip.PrefixFrom(ip, ip.BitLen()).String(), Kind: rule.Kind, Label: rule.Label, Suffix: rule.Suffix, Provider: hostRuleProvider(rule)}, true
		}
	}
	return NetworkClass{}, false
}

// dnsDisplay はDNS失敗だけ名前欄と詳細ID末尾へ反映し、規制用のKindや事業者キーを変えない。
func dnsDisplay(value NetworkClass, status HostDNSStatus, country string) NetworkClass {
	switch status {
	case HostDNSAbsent:
		value.Label = "ｱﾝﾀﾀﾞﾚ"
		value.Suffix = "h"
	case HostDNSMismatch:
		value.Label = country
		if value.Label == "" {
			value.Label = "ZZ"
		}
		value.Suffix = "H"
	}
	return value
}
