// 受理原本の主体選択へ、秘密なしの資格情報と受理枠ルールIDを投影する。
package app

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"slices"
)

// projectAcceptedPrincipal は固定対応を照合した操作から受理枠ルールを取り出す。
// 本文・接続IP・受理枠の主体HMACはこの追加項目へ含めない。
func projectAcceptedPrincipal(p postingProposal, capture map[string]json.RawMessage) (map[string]any, error) {
	_, op, e := acceptedEvidenceFrame(p)
	if e != nil {
		return nil, e
	}
	posts, _, e := acceptedPublicPosts(op)
	if e != nil {
		return nil, e
	}
	out, e := projectPrincipalIdentity(capture)
	if e != nil {
		return nil, e
	}
	for _, key := range []string{"token_validation", "token", "cap", "policy_versions", "overrides"} {
		if raw, ok := capture[key]; ok {
			out[key] = raw
		}
	}
	out["rule_ids"] = acceptedRateRuleIDs(posts)
	out["policy_versions"] = op.Versions
	return out, nil
}

// acceptedRateRuleIDs は確定投稿に記録された受理枠ルールIDを重複なく安定順で返す。
// 規制除外のルールは既存overridesに保持し、ここへ受理枠として混ぜない。
func acceptedRateRuleIDs(posts []domain.Post) []domain.ID {
	ids := []domain.ID{}
	for _, post := range posts {
		if post.Private == nil {
			continue
		}
		for _, key := range post.Private.RateKeys {
			ids = append(ids, key.Rule)
		}
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return slices.Compare(a[:], b[:]) })
	return slices.Compact(ids)
}
