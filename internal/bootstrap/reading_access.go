// 閲覧と管理画面の接続制限を不変スナップショットで共有し、投稿規制から独立して判定する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

var errReadingDenied = errors.New("reading access denied")

// ReadingPolicy はサイト共通・板・管理画面ごとの閲覧条件。OFFでは全条件を無視する。
// 許可CIDRは空なら限定なし。拒否CIDR・UA・回線条件は許可CIDRにも優先する。
// 特殊アドレスはnilで従来条件、trueで回線条件を免除、falseで拒否する。
type ReadingPolicy struct {
	AllowLocalIP    *bool                 `json:"allow_local_ip"`
	AllowLoopbackIP *bool                 `json:"allow_loopback_ip"`
	Enabled         bool                  `json:"enabled"`
	Network         NetworkAccessSettings `json:"network"`
	AllowedCIDRs    []string              `json:"allowed_cidrs"`
	DeniedCIDRs     []string              `json:"denied_cidrs"`
	DeniedAgents    []string              `json:"denied_agents"`
	DenyCrawlers    bool                  `json:"deny_crawlers"`
}

// defaultReadingPolicy は既存サイトの閲覧を変えない初期値を返す。
func defaultReadingPolicy() ReadingPolicy {
	deny := false
	return ReadingPolicy{Network: NetworkAccessSettings{DenyUnresolvedHost: &deny, DeniedKinds: []string{}, DeniedCountries: []string{}, AllowVPN: true}, AllowedCIDRs: []string{}, DeniedCIDRs: []string{}, DeniedAgents: []string{}}
}

type compiledReadingPolicy struct {
	Policy          ReadingPolicy
	Allowed, Denied []netip.Prefix
}
type readingBoardIndex struct{ Boards map[string]*postingBoard }

type readingSnapshot struct {
	Policies       map[string]*compiledReadingPolicy
	PublicRevision domain.U64
}

// compileReadingPolicy は有界入力を検査し、HTTP処理中のCIDR再解析を省く。
func compileReadingPolicy(p ReadingPolicy) (*compiledReadingPolicy, error) {
	if p.Network.DenyUnresolvedHost == nil || p.Network.validate() != nil || p.AllowedCIDRs == nil || p.DeniedCIDRs == nil || p.DeniedAgents == nil || len(p.AllowedCIDRs) > 256 || len(p.DeniedCIDRs) > 256 || len(p.DeniedAgents) > 64 {
		return nil, store.ErrCorrupt
	}
	v := &compiledReadingPolicy{Policy: p}
	for _, group := range []struct {
		raw []string
		dst *[]netip.Prefix
	}{{p.AllowedCIDRs, &v.Allowed}, {p.DeniedCIDRs, &v.Denied}} {
		seen := map[netip.Prefix]bool{}
		for _, raw := range group.raw {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() || seen[prefix] {
				return nil, store.ErrCorrupt
			}
			seen[prefix] = true
			*group.dst = append(*group.dst, prefix)
		}
	}
	seen := map[string]bool{}
	for _, agent := range p.DeniedAgents {
		key := strings.ToLower(agent)
		if !utf8.ValidString(agent) || agent != strings.TrimSpace(agent) || len(agent) == 0 || len(agent) > 256 || strings.ContainsAny(agent, "\r\n\x00") || seen[key] {
			return nil, store.ErrCorrupt
		}
		seen[key] = true
	}
	return v, nil
}

// check は許可リストと拒否条件の積を評価する。分類未取得は指定した国/VPN条件で拒否する。
func (v *compiledReadingPolicy) check(t *identity.NetworkClassifier, ip netip.Addr, agent string, local ...[]identity.NetworkClass) error {
	if v == nil || !v.Policy.Enabled {
		return nil
	}
	if !ip.IsValid() {
		return errReadingDenied
	}
	ip = ip.Unmap()
	allowed := len(v.Allowed) == 0
	for _, prefix := range v.Allowed {
		allowed = allowed || prefix.Contains(ip)
	}
	if !allowed {
		return errReadingDenied
	}
	for _, prefix := range v.Denied {
		if prefix.Contains(ip) {
			return errReadingDenied
		}
	}
	if v.Policy.DenyCrawlers && knownContentCrawler(agent) {
		return errReadingDenied
	}
	lower := strings.ToLower(agent)
	for _, denied := range v.Policy.DeniedAgents {
		if strings.Contains(lower, strings.ToLower(denied)) {
			return errReadingDenied
		}
	}
	permission := v.Policy.AllowLocalIP
	if ip.IsLoopback() {
		permission = v.Policy.AllowLoopbackIP
	} else if !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
		permission = nil
	}
	if permission != nil {
		if !*permission {
			return errReadingDenied
		}
		return nil
	}
	if checkNetworkPermission(t, &v.Policy.Network, ip, local...) != nil {
		return errReadingDenied
	}
	return nil
}

// readingScope は固定スコープと板UUIDだけを受け入れる。
func readingScope(scope string) (domain.ID, error) {
	if scope == "site" || scope == "admin" {
		return domain.ID{}, nil
	}
	var owner domain.ID
	if err := json.Unmarshal([]byte(fmt.Sprintf("%q", scope)), &owner); err != nil || owner == (domain.ID{}) || owner.String() != scope {
		return owner, store.ErrCorrupt
	}
	return owner, nil
}

func validateReadingValue(key string, raw json.RawMessage) error {
	if _, err := readingScope(key); err != nil {
		return err
	}
	var p ReadingPolicy
	if err := strictjson.Decode(raw, &p); err != nil {
		return err
	}
	_, err := compileReadingPolicy(p)
	return err
}

// loadReadingSnapshot は検証済み保存値を起動時にコンパイルする。未保存の旧サイトは無制限。
func loadReadingSnapshot(state store.ControlState) (*readingSnapshot, error) {
	out := &readingSnapshot{Policies: map[string]*compiledReadingPolicy{}}
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "reading_access:") {
			continue
		}
		key := strings.TrimPrefix(name, "reading_access:")
		if err := validateReadingValue(key, row.Value); err != nil {
			return nil, err
		}
		var p ReadingPolicy
		if err := strictjson.Decode(row.Value, &p); err != nil {
			return nil, err
		}
		v, err := compileReadingPolicy(p)
		if err != nil {
			return nil, err
		}
		out.Policies[key] = v
		if key != "admin" {
			out.PublicRevision = max(out.PublicRevision, row.Revision)
		}
	}
	return out, nil
}

// checkReading は管理画面を共通閲覧設定から分離し、板では共通条件と板条件の両方を適用する。
func (r *Repository) checkReading(scope string, ip netip.Addr, agent string) error {
	snapshot := r.liveReading.Load()
	if snapshot == nil {
		return nil
	}
	classifier := r.liveNetworks.Load()
	if scope != "admin" {
		if err := snapshot.Policies["site"].check(classifier, ip, agent); err != nil {
			return err
		}
	}
	if scope != "site" {
		var local []identity.NetworkClass
		if scope != "admin" {
			if index := r.liveReadingBoards.Load(); index != nil {
				if b := index.Boards[scope]; b != nil {
					if networks := b.readingNetworks.Load(); networks != nil {
						local = *networks
					}
				}
			}
		}
		return snapshot.Policies[scope].check(classifier, ip, agent, local)
	}
	return nil
}

// checkCapturedReading は検査済み投稿の接続情報を使い、低水準PostやCAPでも閲覧拒否を迂回させない。
func (r *Repository) checkCapturedReading(scope string, raw []byte) error {
	snapshot := r.liveReading.Load()
	if snapshot == nil {
		return nil
	}
	global, local := snapshot.Policies["site"], snapshot.Policies[scope]
	if (global == nil || !global.Policy.Enabled) && (local == nil || !local.Policy.Enabled) {
		return nil
	}
	var marker struct {
		Schema      string          `json:"schema"`
		Observation json.RawMessage `json:"observation"`
	}
	if err := json.Unmarshal(raw, &marker); err != nil {
		return err
	}
	observationRaw := raw
	if marker.Schema == postcapture.Schema {
		observationRaw = marker.Observation
	}
	var observed struct {
		Resolved evidence.Endpoint         `json:"resolved"`
		Headers  []evidence.ObservedHeader `json:"selected_headers"`
	}
	if err := json.Unmarshal(observationRaw, &observed); err != nil {
		return err
	}
	ip, _ := netip.ParseAddr(observed.Resolved.IP)
	return r.checkReading(scope, ip, observedUserAgent(observed.Headers))
}

// prepareReading は回線種別または逆引きの条件がある時だけ、ワーカー外でDNS候補を準備する。
func (r *Repository) prepareReading(ctx context.Context, scope string, ip netip.Addr) {
	snapshot := r.liveReading.Load()
	if snapshot == nil {
		return
	}
	scopes := []string{scope}
	if scope != "admin" && scope != "site" {
		scopes = append(scopes, "site")
	}
	for _, key := range scopes {
		p := snapshot.Policies[key]
		if p != nil && p.Policy.Enabled && (p.Policy.Network.denyUnresolvedHost() || len(p.Policy.Network.DeniedKinds) > 0) {
			r.resolveNetworkHost(ctx, ip, true)
			return
		}
	}
}
