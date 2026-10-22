// 回収済み案件の元解除をsite署名記録へ照合し、通常案件の照合からだけ分離する。
package bootstrap

import (
	"crypto/ed25519"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// verifiedRetirementIntents は最低reader/site/署名/現在時計を検査した固定一覧だけを返す。
func verifiedRetirementIntents(state store.ControlState, key ed25519.PublicKey, now domain.Time) (map[domain.Hash]disclosure.CaseRetirementIntent, error) {
	var site siteState
	if e := strictjson.Decode(state.Rows["site:state"].Value, &site); e != nil {
		return nil, e
	}
	if e := inspectCaseRetirementRegistry(state, site, key, now); e != nil {
		return nil, e
	}
	rows, e := caseRetirementRegistrations(state, site)
	if e != nil {
		return nil, e
	}
	result := make(map[domain.Hash]disclosure.CaseRetirementIntent, len(rows))
	for fingerprint, row := range rows {
		intent, e := disclosure.VerifyCaseRetirementIntent(row.Event, fingerprint, key)
		if e != nil {
			return nil, e
		}
		result[fingerprint] = intent
	}
	return result, nil
}

// retirementSourceMatches は署名検査済み現在元を先行記録の解除hash/時計へ束縛する。
func retirementSourceMatches(state string, sha domain.Hash, at, now domain.Time, expected domain.Hash) error {
	if expected == (domain.Hash{}) || state != "released" || sha != expected {
		return store.ErrCorrupt
	}
	if at <= 0 || now < at {
		return evidence.ErrRetirementClock
	}
	return nil
}

// requireRetirementSourceSet は登録が期待する元解除の存在と、照合済み集合の一致を要求する。
func requireRetirementSourceSet(intents map[domain.Hash]disclosure.CaseRetirementIntent, seen map[domain.Hash]bool, required bool) error {
	for fingerprint, intent := range intents {
		expected := intent.HTTPRelease
		if required {
			expected = intent.RequiredRelease
		}
		if seen[fingerprint] != (expected != (domain.Hash{})) {
			return store.ErrCorrupt
		}
	}
	return nil
}
