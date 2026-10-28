// 板単位の期限付きIP/CIDR拒否規制。保存型の検査と投稿時評価を共有する。
package bootstrap

import (
	"errors"
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

var ErrPostingDenied = errors.New("posting denied by board rule")

const maxDenyMinutes = 30 * 24 * 60
const permanentDenyMinutes = ^uint32(0)
const permanentDenyExpiry = domain.Time(1<<63 - 1)

type denialScope struct {
	Kind  string    `json:"kind"`
	Board domain.ID `json:"board_id"`
}
type denialCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Unknown  string `json:"unknown_effect"`
}
type denialEffect struct {
	Type    string             `json:"type"`
	IDs     []domain.ID        `json:"ids"`
	Rate    *AdminRateOverride `json:"rate"`
	Stopped *domain.Time       `json:"revoked_at_ns"`
}
type denialRule struct {
	ID           domain.ID               `json:"id"`
	Revision     domain.U64              `json:"revision"`
	Scope        denialScope             `json:"scope"`
	Operations   []string                `json:"operations"`
	Conditions   []denialCondition       `json:"conditions"`
	Effect       denialEffect            `json:"effect"`
	Priority     int32                   `json:"priority"`
	Starts       domain.Time             `json:"starts_at_ns"`
	Expires      domain.Time             `json:"expires_at_ns"`
	Reason       string                  `json:"reason_code"`
	Enabled      bool                    `json:"enabled"`
	ReportPolicy *ReportPolicy           `json:"auto_report_policy"`
	Reports      []autoReportEvidenceRef `json:"auto_report_refs"`
}
type compiledDenial struct {
	rule       denialRule
	prefix     netip.Prefix
	expression *regexp.Regexp
	conditions []compiledRuleCondition
	hasDomains bool
	hasClasses bool
	hasHosts   bool
}

type compiledRuleCondition struct {
	condition  denialCondition
	prefix     netip.Prefix
	expression *regexp.Regexp
}

// denialTarget は曖昧な表記やhost bits付きCIDRを拒否する。mapped IPv6/zoneも管理入力には使わない。
func denialTarget(raw string) (netip.Prefix, string, error) {
	if strings.Contains(raw, "/") {
		p, e := netip.ParsePrefix(raw)
		if e != nil || p.Addr().Is4In6() || p != p.Masked() || p.String() != raw {
			return netip.Prefix{}, "", errors.New("canonical CIDR required")
		}
		return p, "network", nil
	}
	a, e := netip.ParseAddr(raw)
	if e != nil || a.Is4In6() || a.Zone() != "" || a.String() != raw {
		return netip.Prefix{}, "", errors.New("canonical IP required")
	}
	return netip.PrefixFrom(a, a.BitLen()), "ip", nil
}
func validDenyOperations(v []string) bool {
	return len(v) == 1 && (v[0] == "create" || v[0] == "reply") || len(v) == 2 && v[0] == "create" && v[1] == "reply"
}
func validDenyReason(s string) bool { return s == "spam" || s == "abuse" || s == "manual" }
func compileDenial(r denialRule) (compiledDenial, error) {
	if r.ID == (domain.ID{}) || r.Scope.Kind != "board" || r.Scope.Board == (domain.ID{}) || !validDenyOperations(r.Operations) || len(r.Conditions) < 1 || len(r.Conditions) > 8 || !validRuleEffect(r.Effect) || r.Priority != 0 || !validDenyReason(r.Reason) || r.Starts <= 0 || r.Expires <= r.Starts || (r.Expires-r.Starts > domain.Time(maxDenyMinutes)*domain.Time(time.Minute) && !tokenDenyRule(r)) || !(r.Revision == 1 && r.Enabled || r.Revision == 2 && !r.Enabled) {
		return compiledDenial{}, store.ErrCorrupt
	}
	if r.Effect.Stopped != nil && (r.Enabled || *r.Effect.Stopped < r.Starts) || r.Effect.Type == "rate_override" && !r.Enabled && r.Effect.Stopped == nil {
		return compiledDenial{}, store.ErrCorrupt
	}
	if err := validateAutoReportRefs(r); err != nil {
		return compiledDenial{}, err
	}
	out := compiledDenial{rule: r}
	seen := map[denialCondition]bool{}
	for _, c := range r.Conditions {
		if seen[c] {
			return compiledDenial{}, store.ErrCorrupt
		}
		seen[c] = true
		prefix, expression, e := compileDenialCondition(c)
		if e != nil {
			return compiledDenial{}, e
		}
		out.conditions = append(out.conditions, compiledRuleCondition{c, prefix, expression})
		out.hasDomains = out.hasDomains || c.Field == "domain"
		out.hasClasses = out.hasClasses || c.Field == "line"
		out.hasHosts = out.hasHosts || c.Field == "host"
		// 回線表の変更後も受理枠復旧を壊さないよう、初版の回線分類条件は拒否だけにする。
		if (c.Field == "line" || c.Field == "host") && r.Effect.Type != "deny" {
			return compiledDenial{}, store.ErrCorrupt
		}
	}
	out.prefix, out.expression = out.conditions[0].prefix, out.conditions[0].expression
	return out, nil
}

func validateDenialRule(key string, old, next []byte) error {
	var r denialRule
	if e := strictjson.Decode(next, &r); e != nil {
		return e
	}
	if key != r.ID.String() {
		return store.ErrCorrupt
	}
	if _, e := compileDenial(r); e != nil {
		return e
	}
	if len(old) == 0 {
		if r.Revision != 1 || !r.Enabled {
			return store.ErrCorrupt
		}
		return nil
	}
	var p denialRule
	if e := strictjson.Decode(old, &p); e != nil {
		return e
	}
	if !p.Enabled || p.Revision != 1 || r.Enabled || r.Revision != 2 {
		return store.ErrCorrupt
	}
	p.Enabled = false
	p.Revision = 2
	if r.Effect.Type == "rate_override" || r.Effect.Type == "allow_rule_ids" {
		p.Effect.Stopped = r.Effect.Stopped
	}
	if !reflect.DeepEqual(p, r) {
		return errors.New("rule can only be revoked")
	}
	return nil
}

// loadDenials は起動時に対象所有者を照合し、評価用prefixを一度だけ構築する。
func (b *postingBoard) loadDenials() error {
	b.denials = map[domain.ID]compiledDenial{}
	for key, row := range b.control.State().Rows {
		if !strings.HasPrefix(key, "board_rule:") {
			continue
		}
		var r denialRule
		if e := strictjson.Decode(row.Value, &r); e != nil {
			return e
		}
		c, e := compileDenial(r)
		if e != nil || r.Scope.Board != b.owner {
			return store.ErrCorrupt
		}
		for _, ref := range r.Reports {
			if !b.matchesKey(ref.Target.Board) {
				return store.ErrCorrupt
			}
		}
		b.denials[r.ID] = c
	}
	if len(b.denials) > 1000 {
		return errors.New("board rule capacity exceeded")
	}
	if e := validateAllowedReferences(b.denials); e != nil {
		return e
	}
	if b.admission != nil {
		b.admission.installOverrides(b.owner, b.denials)
	}
	return validateOverrideHistory(b.denials)
}

// checkDenials は受理済み再送の照会後・新しい受理枠の予約前に呼ぶ。条件やIPを公開応答へ渡さない。
func (b *postingBoard) checkDenials(ip netip.Addr, create bool, now domain.Time) error {
	denied, _, e := b.matchingRules(ip, postinput.Input{}, domain.Hash{}, create, now)
	if e != nil {
		return e
	}
	if denied {
		return ErrPostingDenied
	}
	return nil
}

func (b *postingBoard) sortedDenials() []denialRule {
	out := make([]denialRule, 0, len(b.denials))
	for _, v := range b.denials {
		out = append(out, v.rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out
}

// inspectRuleRow は復旧時に板所有者とreceiptの参照先を検証する。期限経過だけでは保存行を捨てない。
func inspectRuleRow(key string, row store.ControlRow, board domain.ID, state store.ControlState) error {
	if row.Expires != nil {
		return store.ErrCorrupt
	}
	if strings.HasPrefix(key, "board_rule:") {
		var r denialRule
		if e := strictjson.Decode(row.Value, &r); e != nil {
			return e
		}
		if r.Effect.Type == "allow_rule_ids" {
			for _, id := range r.Effect.IDs {
				var target denialRule
				row, ok := state.Rows["board_rule:"+id.String()]
				if !ok || strictjson.Decode(row.Value, &target) != nil || target.Scope.Board != board || target.Effect.Type == "allow_rule_ids" || target.Starts > r.Starts || target.Expires <= r.Starts {
					return store.ErrCorrupt
				}
			}
		}
		if r.Scope.Board != board {
			return store.ErrCorrupt
		}
		return nil
	}
	var receipt ruleReceipt
	if e := strictjson.Decode(row.Value, &receipt); e != nil {
		return e
	}
	var current denialRule
	target, ok := state.Rows["board_rule:"+receipt.Result.ID.String()]
	if !ok || strictjson.Decode(target.Value, &current) != nil || receipt.Result.Scope.Board != board || receipt.Result.Revision > current.Revision {
		return store.ErrCorrupt
	}
	result := receipt.Result
	result.Enabled = current.Enabled
	result.Revision = current.Revision
	result.Effect.Stopped = current.Effect.Stopped
	if !reflect.DeepEqual(result, current) {
		return store.ErrCorrupt
	}
	return nil
}

// permanentTokenRule は板内の匿名主体への拒否だけを無期限として扱う。
func permanentTokenRule(r denialRule) bool {
	return r.Expires == permanentDenyExpiry && r.Effect.Type == "deny" && len(r.Conditions) == 1 && r.Conditions[0].Field == "token" && r.Conditions[0].Operator == "exact"
}

// tokenDenyRule は長期規制を匿名主体の完全一致拒否だけに限定する。
func tokenDenyRule(r denialRule) bool {
	return r.Effect.Type == "deny" && len(r.Conditions) == 1 && r.Conditions[0].Field == "token" && r.Conditions[0].Operator == "exact" && (r.Expires == permanentDenyExpiry || r.Expires-r.Starts <= domain.Time(maxCapBanMinutes)*60e9)
}
