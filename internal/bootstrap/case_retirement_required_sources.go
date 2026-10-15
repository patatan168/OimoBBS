// 回収済み案件の必須元解除を現在全板集合へ照合し、通常案件/元検査へ渡す集合を作る。
package bootstrap

import (
	"crypto/ed25519"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// requiredSourcesWithRetirements は欠落/重複/未解除/差替えを拒否し、案件不在の正しい解除だけを分離する。
// 元は所有者が署名/reader/全時計床を検査済みの現在snapshotに限る。元台帳は変更しない。
func requiredSourcesWithRetirements(state store.ControlState, key ed25519.PrivateKey, cases []disclosure.RequiredCaseInspection, sources requiredHoldSourceSnapshots, now domain.Time) (requiredHoldSourceSnapshots, error) {
	intents, e := verifiedRetirementIntents(state, key.Public().(ed25519.PublicKey), now)
	if e != nil {
		return requiredHoldSourceSnapshots{}, e
	}
	live := map[domain.ID]bool{}
	for _, c := range cases {
		live[c.Current.ID] = true
	}
	seen := map[domain.Hash]bool{}
	archived := map[domain.ID]bool{}
	result := requiredHoldSourceSnapshots{}
	for _, receipt := range sources.Receipts {
		fingerprint, e := disclosure.CaseRetirementFingerprint(key, receipt.Binding.Case)
		if e != nil {
			return result, e
		}
		found, e := checkRetirementRequiredReceipt(intents, seen, fingerprint, receipt, now)
		if e != nil {
			return result, e
		}
		archived[receipt.Binding.Case] = found && !live[receipt.Binding.Case]
		if !archived[receipt.Binding.Case] {
			result.Receipts = append(result.Receipts, receipt)
		}
	}
	if e = requireRetirementSourceSet(intents, seen, true); e != nil {
		return result, e
	}
	result.Renewals = liveRequiredRenewals(sources.Renewals, archived)
	return result, nil
}

// liveRequiredRenewals は現在案件の延長証明を維持し、照合済み回収案件の証明だけを分離する。
func liveRequiredRenewals(renewals []app.RequiredHoldRenewalReceipt, archived map[domain.ID]bool) []app.RequiredHoldRenewalReceipt {
	result := []app.RequiredHoldRenewalReceipt{}
	for _, renewal := range renewals {
		if !archived[renewal.Original.Binding.Case] {
			result = append(result, renewal)
		}
	}
	return result
}

// checkRetirementRequiredReceipt は登録に対応する現在解除を検査し、重複を拒否する。
func checkRetirementRequiredReceipt(intents map[domain.Hash]disclosure.CaseRetirementIntent, seen map[domain.Hash]bool, fingerprint domain.Hash, receipt app.RequiredHoldReceipt, now domain.Time) (bool, error) {
	intent, found := intents[fingerprint]
	if !found {
		return false, nil
	}
	if seen[fingerprint] {
		return true, store.ErrCorrupt
	}
	if e := retirementSourceMatches(receipt.State, receipt.SHA, receipt.At, now, intent.RequiredRelease); e != nil {
		return true, e
	}
	seen[fingerprint] = true
	return true, nil
}
