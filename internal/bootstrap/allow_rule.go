// 指定規制だけを条件付きで除外する。一般許可や管理権限への昇格として使わない。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"slices"
	"strconv"
	"strings"
)

func validAllowedRuleIDs(ids []domain.ID) bool {
	if len(ids) < 1 || len(ids) > 128 {
		return false
	}
	prior := ""
	for _, id := range ids {
		if id == (domain.ID{}) || id.String() <= prior {
			return false
		}
		prior = id.String()
	}
	return true
}
func validRuleEffect(effect denialEffect) bool {
	if effect.Type == "rate_override" {
		return len(effect.IDs) == 0 && effect.Rate != nil && effect.Rate.valid()
	}
	if effect.Rate != nil {
		return false
	}
	if effect.Type == "allow_rule_ids" {
		return validAllowedRuleIDs(effect.IDs)
	}
	return (effect.Type == "deny" || effect.Type == "require_token") && len(effect.IDs) == 0 && effect.Stopped == nil
}

// validateAllowedTargets は発行時に同じ板の現在有効なdeny/require_tokenだけを参照させる。
func validateAllowedTargets(rules map[domain.ID]compiledDenial, ids []domain.ID, at domain.Time) error {
	for _, id := range ids {
		target, ok := rules[id]
		if !ok || target.rule.Effect.Type == "allow_rule_ids" || !target.rule.Enabled || at < target.rule.Starts || at >= target.rule.Expires {
			return store.ErrCorrupt
		}
	}
	return nil
}

// composeMatchedRules は全条件一致の集合を作った後で許可を反映し、map順序へ依存しない。
func composeMatchedRules(matched map[domain.ID]denialRule) (bool, bool) {
	excluded := excludedRules(matched)
	denied, required := false, false
	for id, rule := range matched {
		if excluded[id] {
			continue
		}
		switch rule.Effect.Type {
		case "deny":
			denied = true
		case "require_token":
			required = true
		}
	}
	return denied, required
}

// validateAllowedReferences は停止済みの元規制も保持し、欠落・自己参照・許可同士の参照を拒否する。
func validateAllowedReferences(rules map[domain.ID]compiledDenial) error {
	for _, entry := range rules {
		rule := entry.rule
		if rule.Effect.Type != "allow_rule_ids" {
			continue
		}
		for _, id := range rule.Effect.IDs {
			target, ok := rules[id]
			if !ok || target.rule.Effect.Type == "allow_rule_ids" || target.rule.Scope.Board != rule.Scope.Board || target.rule.Starts > rule.Starts || target.rule.Expires <= rule.Starts {
				return store.ErrCorrupt
			}
		}
	}
	return nil
}

// parseAllowedRuleIDs はHTMLの空白区切りIDを正規形の集合へ変換する。
func parseAllowedRuleIDs(raw string) ([]domain.ID, error) {
	ids := []domain.ID{}
	for _, word := range strings.Fields(raw) {
		var id domain.ID
		if json.Unmarshal([]byte(strconv.Quote(word)), &id) != nil || id.String() != word {
			return nil, store.ErrCorrupt
		}
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return strings.Compare(a.String(), b.String()) })
	if !validAllowedRuleIDs(ids) {
		return nil, store.ErrCorrupt
	}
	return ids, nil
}

func excludedRules(matched map[domain.ID]denialRule) map[domain.ID]bool {
	excluded := map[domain.ID]bool{}
	for _, rule := range matched {
		if rule.Effect.Type == "allow_rule_ids" {
			for _, id := range rule.Effect.IDs {
				excluded[id] = true
			}
		}
	}
	return excluded
}
