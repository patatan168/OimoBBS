// 掲示板全体の投稿規制をサイトcontrolへ保存し、全板と新設板へ共通適用する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"regexp"
	"strings"
	"time"
)

const globalRulesReader uint32 = 103

// GlobalPostingRule は全板に適用する投稿条件。期限0は無期限。
type GlobalPostingRule struct {
	ID        domain.ID   `json:"id"`
	Field     string      `json:"field"`
	Operator  string      `json:"operator"`
	Value     string      `json:"value"`
	Operation string      `json:"operation"`
	Mode      string      `json:"mode"`
	Starts    domain.Time `json:"starts_at_ns"`
	Expires   domain.Time `json:"expires_at_ns"`
	Enabled   bool        `json:"enabled"`
}

// GlobalRuleSettings は全板共通規制の現行値。解除した履歴も保持する。
type GlobalRuleSettings struct {
	Rules []GlobalPostingRule `json:"rules"`
}
type compiledGlobalRule struct {
	rule      GlobalPostingRule
	condition compiledRuleCondition
}
type globalRuleSet struct{ rules []compiledGlobalRule }

// AdminGlobalRules は一覧と競合検出用の版。
type AdminGlobalRules struct {
	Settings GlobalRuleSettings `json:"settings"`
	Revision domain.U64         `json:"revision"`
}

// ETag は全板共通規制の保存版を返す。
func (v AdminGlobalRules) ETag() string { return fmt.Sprintf(`"global-rules:%d"`, v.Revision) }

func (v GlobalRuleSettings) validate() error {
	if v.Rules == nil || len(v.Rules) > 1000 {
		return store.ErrCorrupt
	}
	seen := map[domain.ID]bool{}
	for _, r := range v.Rules {
		if r.ID == (domain.ID{}) || seen[r.ID] || r.Starts <= 0 || r.Expires != 0 && r.Expires <= r.Starts || r.Mode != "observe" && r.Mode != "reject" || r.Operation != "both" && r.Operation != "create" && r.Operation != "reply" {
			return store.ErrCorrupt
		}
		seen[r.ID] = true
		switch r.Field {
		case "body", "title", "name", "mail", "ip", "network", "domain", "all":
		default:
			return store.ErrCorrupt
		}
		if r.Field == "all" {
			if r.Operator != "exact" || r.Value != "*" {
				return store.ErrCorrupt
			}
			continue
		}
		if strings.TrimSpace(r.Value) == "" {
			return store.ErrCorrupt
		}
		if _, _, err := compileDenialCondition(denialCondition{r.Field, r.Operator, r.Value, "deny"}); err != nil {
			return err
		}
	}
	return nil
}
func validateGlobalRules(key string, old, next json.RawMessage) error {
	var v GlobalRuleSettings
	if key != "active" || strictjson.Decode(next, &v) != nil || v.validate() != nil {
		return store.ErrCorrupt
	}
	if len(old) == 0 {
		return nil
	}
	var before GlobalRuleSettings
	if strictjson.Decode(old, &before) != nil {
		return store.ErrCorrupt
	}
	if len(v.Rules) < len(before.Rules) {
		return store.ErrCorrupt
	}
	for i, r := range before.Rules {
		after := v.Rules[i]
		enabled := after.Enabled
		after.Enabled = r.Enabled
		if after != r || !r.Enabled && enabled {
			return store.ErrCorrupt
		}
	}
	return nil
}

func (r *Repository) globalRulesViewLocked() AdminGlobalRules {
	v := AdminGlobalRules{Settings: GlobalRuleSettings{Rules: []GlobalPostingRule{}}}
	if row, ok := r.site.State().Rows["global_rules:active"]; ok {
		_ = strictjson.Decode(row.Value, &v.Settings)
		v.Revision = row.Revision
	}
	return v
}

// publishGlobalRules は保存済み条件を一度だけ構築して検出器へ公開する。guard mutexは呼出元で取得しない。
func (r *Repository) publishGlobalRules(value GlobalRuleSettings) {
	set := &globalRuleSet{}
	for _, rule := range value.Rules {
		c := denialCondition{rule.Field, rule.Operator, rule.Value, "deny"}
		var prefix netip.Prefix
		var re *regexp.Regexp
		if rule.Field != "all" {
			prefix, re, _ = compileDenialCondition(c)
		}
		set.rules = append(set.rules, compiledGlobalRule{rule, compiledRuleCondition{condition: c, prefix: prefix, expression: re}})
	}
	r.guard.mu.Lock()
	r.guard.globalRules = set
	r.guard.mu.Unlock()
}

func (g *abuseGuard) checkGlobalRules(e guardEntry) error {
	if g.globalRules == nil {
		return nil
	}
	operation := "reply"
	if e.create {
		operation = "create"
	}
	in := postinput.Input{Body: e.body, Name: e.name, Mail: e.mail, Title: e.title}
	var hosts []string
	for _, c := range g.globalRules.rules {
		if c.rule.Enabled && c.rule.Field == "domain" {
			hosts = postingURLHosts(in.Body)
			break
		}
	}
	ip, _ := netip.ParseAddr(e.rawIP)
	for _, c := range g.globalRules.rules {
		r := c.rule
		if !r.Enabled || e.at < r.Starts || r.Expires != 0 && e.at >= r.Expires || r.Operation != "both" && r.Operation != operation {
			continue
		}
		if r.Field != "all" && !c.condition.matches(ip, in, e.token, hosts, nil) {
			continue
		}
		g.recordSecurity(e, "global_rule", "掲示板全体の投稿規制："+r.ID.String(), r.Mode == "reject")
		if r.Mode == "reject" {
			return ErrPostingDenied
		}
	}
	return nil
}

// Active は期限と解除状態を現在時刻で表示する。
func (r GlobalPostingRule) Active() bool {
	now := domain.Time(time.Now().UnixNano())
	return r.Enabled && now >= r.Starts && (r.Expires == 0 || now < r.Expires)
}

// ExpiryLabel は管理画面の期限を日本時間で返す。
func (r GlobalPostingRule) ExpiryLabel() string {
	if r.Expires == 0 {
		return "無期限"
	}
	return time.Unix(0, int64(r.Expires)).In(time.FixedZone("JST", 9*3600)).Format("2006-01-02 15:04")
}

// FieldLabel は規制対象の日本語名を返す。
func (r GlobalPostingRule) FieldLabel() string {
	return map[string]string{"body": "本文", "title": "スレッド名", "name": "名前", "mail": "メール欄", "ip": "IP", "network": "IP範囲", "domain": "URLのドメイン", "all": "すべての投稿"}[r.Field]
}

// OperatorLabel は一致条件の日本語名を返す。
func (r GlobalPostingRule) OperatorLabel() string {
	return map[string]string{"exact": "完全一致", "contains": "部分一致", "regexp": "正規表現", "suffix": "ドメイン一致（子ドメイン含む）", "cidr": "範囲一致"}[r.Operator]
}
