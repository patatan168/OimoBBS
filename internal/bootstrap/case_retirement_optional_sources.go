// 回収済み案件のHTTP元解除を先行署名へ照合し、通常案件の範囲/集合検査を維持する。
package bootstrap

import (
	"crypto/ed25519"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"time"
)

// optionalHoldRetirementCheck は署名検査済み登録と現在元の照合後だけ、通常案件検査を実行する。
func optionalHoldRetirementCheck(cases []disclosure.Case, intents map[domain.Hash]disclosure.CaseRetirementIntent, fingerprint func(domain.ID) domain.Hash, now domain.Time) func(evidence.OptionalHoldReferences) error {
	live := map[domain.ID]bool{}
	for _, c := range cases {
		live[c.ID] = true
	}
	return func(source evidence.OptionalHoldReferences) error {
		rows, e := source.OptionalHoldReceipts()
		if e != nil {
			return e
		}
		filtered, e := optionalSourcesWithRetirements(rows, live, intents, fingerprint, now)
		if e != nil {
			return e
		}
		return optionalHoldCasesCheck(cases)(retirementOptionalReferences{source, filtered})
	}
}

// retirementOptionalReferences は現在元の検査/保護を維持し、検査済み解除の集合だけを分離する。
type retirementOptionalReferences struct {
	evidence.OptionalHoldReferences
	rows []evidence.OptionalHoldReceipt
}

func (s retirementOptionalReferences) OptionalHoldReceipts() ([]evidence.OptionalHoldReceipt, error) {
	return s.rows, nil
}

// optionalSourcesWithRetirements は期待解除の完全一致を確認し、現在案件不在の対応済み元だけを分離する。
func optionalSourcesWithRetirements(rows []evidence.OptionalHoldReceipt, live map[domain.ID]bool, intents map[domain.Hash]disclosure.CaseRetirementIntent, fingerprint func(domain.ID) domain.Hash, now domain.Time) ([]evidence.OptionalHoldReceipt, error) {
	return optionalSourcesWithCompletedRetirements(rows, live, intents, fingerprint, now, nil)
}

// optionalSourcesWithCompletedRetirements は現在索引/登録で検査済みの不在だけを元解除の代わりに認める。
func optionalSourcesWithCompletedRetirements(rows []evidence.OptionalHoldReceipt, live map[domain.ID]bool, intents map[domain.Hash]disclosure.CaseRetirementIntent, fingerprint func(domain.ID) domain.Hash, now domain.Time, completed map[domain.Hash]bool) ([]evidence.OptionalHoldReceipt, error) {
	seen := map[domain.Hash]bool{}
	result := []evidence.OptionalHoldReceipt{}
	for _, row := range rows {
		hash := fingerprint(row.Binding.Case)
		intent, found := intents[hash]
		if found {
			if seen[hash] {
				return nil, store.ErrCorrupt
			}
			if e := retirementSourceMatches(row.State, row.SHA, row.At, now, intent.HTTPRelease); e != nil {
				return nil, e
			}
			seen[hash] = true
		}
		if !found || live[row.Binding.Case] {
			result = append(result, row)
		}
	}
	if err := checkCompletedRetirementSourceSet(intents, seen, completed); err != nil {
		return nil, err
	}
	return result, nil
}

// checkedOptionalHoldCases はsite/署名/時計を現在排他下で確認し、元所有者内の照合を返す。
// callbackを使う間はlifecycle排他を保持し、案件所有者を閉じない。
func (r *Repository) checkedOptionalHoldCases(cases []disclosure.Case, now time.Time) (func(evidence.OptionalHoldReferences) error, error) {
	seed, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return nil, e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	at := domain.Time(now.UnixNano())
	intents, e := verifiedRetirementIntents(r.site.State(), key.Public().(ed25519.PublicKey), at)
	if e != nil {
		return nil, e
	}
	return optionalHoldRegisteredCheck(r.cfg.DataDir, key, r.site.State(), cases, intents, r.evidenceCases.CaseRetirementFingerprint, at)
}

// checkCompletedRetirementSourceSet は実参照と完了証明の重複を拒否し、期待集合を完全照合する。
func checkCompletedRetirementSourceSet(intents map[domain.Hash]disclosure.CaseRetirementIntent, seen, completed map[domain.Hash]bool) error {
	for hash := range completed {
		if seen[hash] {
			return store.ErrCorrupt
		}
		seen[hash] = true
	}
	return requireRetirementSourceSet(intents, seen, false)
}
