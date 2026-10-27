// 投稿者規制の簡易表示が、別主体や条件付き規制を取り違えず一覧の後方も検索することを確認する。
package bootstrap

import (
	"strings"
	"testing"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
)

func TestMatchingSubjectRulesScopeAndPagination(t *testing.T) {
	now := time.Now()
	target := strings.Repeat("a", 64)
	makeRule := func() AdminRule {
		return AdminRule{ID: domain.NewID(), Enabled: true, Target: target, Match: AdminRuleMatch{Field: "token", Operator: "exact", Effect: "deny"}, Expires: now.Add(time.Hour).Format(time.RFC3339Nano)}
	}
	var rules []AdminRule
	for range 60 {
		rule := makeRule()
		rule.Target = strings.Repeat("b", 64)
		rules = append(rules, rule)
	}
	activeIDs := map[domain.ID]bool{}
	for range 55 {
		active := makeRule()
		activeIDs[active.ID] = true
		rules = append(rules, active)
	}
	expired, revoked, composite, ip, allow := makeRule(), makeRule(), makeRule(), makeRule(), makeRule()
	expired.Expires = now.Add(-time.Second).Format(time.RFC3339Nano)
	revoked.Enabled = false
	composite.Extra = []AdminRuleCondition{{Field: "ua", Operator: "exact", Value: "agent"}}
	ip.Match.Field = "ip"
	allow.Match.Effect = "allow_rule_ids"
	rules = append(rules, expired, revoked, composite, ip, allow)
	rows, total := matchingSubjectRules(rules, target, adminauth.Session{}, "/api/v1/boards/example/rules", now)
	if total != 55 || len(rows) != 50 {
		t.Fatal("selection must precede display limit", total, len(rows))
	}
	for _, row := range rows {
		if !activeIDs[row.Rule.ID] || row.CSRF == "" || row.RequestID == "" {
			t.Fatal("wrong rule selected", row.Rule.ID)
		}
	}
}
