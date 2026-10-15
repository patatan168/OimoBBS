// 規制条件を登録・復旧時に一度だけ構築する。投稿本文を外部照会や監査へ渡さない。
package bootstrap

import (
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/postinput"
	"regexp"
	"strings"
	"unicode/utf8"
)

// AdminRuleMatch はIP/CIDR以外の条件と規制効果。省略時は従来のIP/CIDR拒否になる。
type AdminRuleMatch struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Effect   string `json:"effect"`
}

func (i AdminRuleInput) match() AdminRuleMatch {
	if i.Match != nil {
		return *i.Match
	}
	_, field, _ := denialTarget(i.Target)
	op := "exact"
	if field == "network" {
		op = "cidr"
	}
	return AdminRuleMatch{field, op, "deny"}
}

// compileDenialCondition は保存前・復旧時に条件型と上限を検査し、正規表現を一度だけ構築する。
func compileDenialCondition(c denialCondition) (netip.Prefix, *regexp.Regexp, error) {
	bad := errors.New("invalid rule condition")
	if c.Unknown != "deny" || !utf8.ValidString(c.Value) || len(c.Value) == 0 || len(c.Value) > 1024 {
		return netip.Prefix{}, nil, bad
	}
	switch c.Field {
	case "ip", "network":
		p, field, e := denialTarget(c.Value)
		op := "exact"
		if field == "network" {
			op = "cidr"
		}
		if e != nil || c.Field != field || c.Operator != op {
			return netip.Prefix{}, nil, bad
		}
		return p, nil, nil
	case "line":
		if c.Operator != "exact" || !identity.ValidNetworkKind(c.Value) {
			return netip.Prefix{}, nil, bad
		}
	case "token":
		var hash domain.Hash
		if c.Operator != "exact" || json.Unmarshal([]byte(`"`+c.Value+`"`), &hash) != nil || hash == (domain.Hash{}) {
			return netip.Prefix{}, nil, bad
		}
	case "domain", "host":
		if c.Field == "host" {
			if _, err := netip.ParseAddr(c.Value); err == nil {
				return netip.Prefix{}, nil, bad
			}
		}
		if c.Operator != "exact" && c.Operator != "suffix" || !validRuleDomain(c.Value) {
			return netip.Prefix{}, nil, bad
		}
		if _, e := netip.ParseAddr(c.Value); e == nil && c.Operator != "exact" {
			return netip.Prefix{}, nil, bad
		}
	case "name", "mail", "title", "body", "ua":
		switch c.Operator {
		case "exact", "contains":
		case "regexp":
			re, e := regexp.Compile(c.Value)
			return netip.Prefix{}, re, e
		default:
			return netip.Prefix{}, nil, bad
		}
	default:
		return netip.Prefix{}, nil, bad
	}
	return netip.Prefix{}, nil, nil
}

// validRuleDomain はASCIIのDNS名とcanonical IPv4だけを受け付け、条件値の曖昧な解釈を防ぐ。
func validRuleDomain(raw string) bool {
	if len(raw) > 253 || raw != strings.ToLower(raw) || strings.ContainsAny(raw, "/:@[]% \\?#\r\n") {
		return false
	}
	if ip, e := netip.ParseAddr(raw); e == nil {
		return ip.Is4() && ip.String() == raw
	}
	for _, label := range strings.Split(raw, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

var ruleURLs = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)

// matches は秘密除去済みの入力・認証済み主体・観測UAを事前構築した全条件へ照合する。
func (c compiledDenial) matches(ip netip.Addr, in postinput.Input, token domain.Hash, hosts, agents []string, classes ...string) bool {
	for _, condition := range c.conditions {
		if !condition.matches(ip, in, token, hosts, agents, classes...) {
			return false
		}
	}
	return true
}

// matches は一つの事前構築済み条件を照合する。全条件が一致した場合だけ規制を適用する。
func (c compiledRuleCondition) matches(ip netip.Addr, in postinput.Input, token domain.Hash, hosts, agents []string, classes ...string) bool {
	condition := c.condition
	var value string
	switch condition.Field {
	case "line":
		kind := "unknown"
		if len(classes) > 0 {
			kind = classes[0]
		}
		return kind == condition.Value || condition.Value == "mobile" && kind == "mvno"
	case "ip", "network":
		return !ip.IsValid() || c.prefix.Contains(ip.Unmap())
	case "token":
		return token != (domain.Hash{}) && token.String() == condition.Value
	case "host":
		if len(classes) < 2 || classes[1] == "" {
			return false
		}
		return classes[1] == condition.Value || condition.Operator == "suffix" && strings.HasSuffix(classes[1], "."+condition.Value)
	case "domain":
		for _, host := range hosts {
			if host == condition.Value || condition.Operator == "suffix" && strings.HasSuffix(host, "."+condition.Value) {
				return true
			}
		}
		return false
	case "name":
		value = in.Name
	case "mail":
		value = in.Mail
	case "title":
		value = in.Title
	case "body":
		value = in.Body
	case "ua":
		for _, agent := range agents {
			if c.matchesText(agent) {
				return true
			}
		}
		return false
	}
	return c.matchesText(value)
}

func (c compiledRuleCondition) matchesText(value string) bool {
	condition := c.condition
	switch condition.Operator {
	case "exact":
		return value == condition.Value
	case "contains":
		return strings.Contains(value, condition.Value)
	case "regexp":
		return c.expression.MatchString(value)
	}
	return false
}

// matchingRules は期限・開始時計と対象操作を検査する。再送確定後の拒否と確認前のCookie要件で共有する。
func (b *postingBoard) matchingRules(ip netip.Addr, in postinput.Input, token domain.Hash, create bool, now domain.Time) (bool, bool, error) {
	return b.matchingObservedRules(ip, in, token, create, now, nil)
}

// matchingObservedRules は既存のHTTP観測からUAを照合し、DNSや追加の通信を行わない。
// 同名ヘッダの各値を評価し、先頭に正常値を置くことによる後続値の規制迂回を防ぐ。
func (b *postingBoard) matchingObservedRules(ip netip.Addr, in postinput.Input, token domain.Hash, create bool, now domain.Time, headers []evidence.ObservedHeader) (bool, bool, error) {
	matched, err := b.matchedRules(ip, in, token, create, now, headers, false)
	denied, required := composeMatchedRules(matched)
	return denied, required, err
}

// matchedRules は現在の適用と受理時点の追加枠の照合に同じ条件評価器を使う。
func (b *postingBoard) matchedRules(ip netip.Addr, in postinput.Input, token domain.Hash, create bool, now domain.Time, headers []evidence.ObservedHeader, historical bool) (map[domain.ID]denialRule, error) {
	operation := "reply"
	if create {
		operation = "create"
	}
	matched := map[domain.ID]denialRule{}
	var hosts []string
	domainsParsed := false
	agents := []string{}
	for _, h := range headers {
		if h.Name == "User-Agent" {
			for _, value := range h.Values {
				agents = append(agents, value.Display)
			}
		}
	}
	if len(agents) == 0 {
		agents = []string{""}
	}
	class := "unknown"
	for _, v := range b.denials {
		if v.hasClasses {
			line, e := b.networkClass(ip.String())
			if e != nil {
				return nil, e
			}
			class = line.Kind
			break
		}
	}
	for _, v := range b.denials {
		rule := v.rule
		if !historical && rule.Enabled && now < rule.Starts {
			return nil, ErrPostingUnavailable
		}
		if now < rule.Starts || now >= rule.Expires || !rule.Enabled && (!historical || rule.Effect.Stopped == nil || now >= *rule.Effect.Stopped) {
			continue
		}
		for _, op := range rule.Operations {
			if op != operation {
				continue
			}
			if v.hasDomains && !domainsParsed {
				hosts = postingURLHosts(in.Body)
				domainsParsed = true
			}
			hostname := ""
			if v.hasHosts && b.networkHosts != nil {
				hostname = b.networkHosts.Hostname(ip)
			}
			if !v.matches(ip, in, token, hosts, agents, class, hostname) {
				continue
			}
			matched[rule.ID] = rule
		}
	}
	return matched, nil
}

// postingURLHosts は本文のURLを一要求で一度だけ解析する。外部へのDNS/HTTP照会は行わない。
func postingURLHosts(body string) []string {
	hosts := []string{}
	for _, raw := range ruleURLs.FindAllString(body, -1) {
		u, e := url.Parse(strings.TrimRight(raw, ".,;!?)]}。、）】」』"))
		if e != nil || u.Host == "" {
			continue
		}
		hosts = append(hosts, strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")))
	}
	return hosts
}
