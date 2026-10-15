// 管理履歴回収候補の解除hashを元所有者の署名検査済み最新参照へ照合する。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// CheckCaseRetirementSources は候補の元解除参照を現在の全所有者snapshotと照合する。
// 呼出元は所有排他と署名/reader/全時計床の検査を済ませ、待ち後にも候補の版/hashを再確認する。
// この検査だけで削除を許可せず、同案件の重複・欠落・未解除・hash差替えを拒否する。
func CheckCaseRetirementSources(candidate CaseRetirementCandidate, required []app.RequiredHoldReceipt, optional []evidence.OptionalHoldReceipt, now domain.Time) error {
	if candidate.Case == (domain.ID{}) || candidate.Head == (domain.Hash{}) || candidate.Revision == 0 || candidate.EligibleAt <= 0 || candidate.Clock <= 0 {
		return ErrInvalid
	}
	if now < max(candidate.EligibleAt, candidate.Clock) {
		return ErrExpired
	}
	if e := checkRetirementRequiredSource(candidate, required, now); e != nil {
		return e
	}
	return checkRetirementHTTPSource(candidate, optional, now)
}

func checkRetirementRequiredSource(candidate CaseRetirementCandidate, rows []app.RequiredHoldReceipt, now domain.Time) error {
	found := false
	for _, row := range rows {
		if row.Binding.Case != candidate.Case {
			continue
		}
		if found {
			return store.ErrCorrupt
		}
		if e := checkRetirementSourceRelease(row.State, row.SHA, row.At, candidate.RequiredRelease, now); e != nil {
			return e
		}
		found = true
	}
	if found != (candidate.RequiredRelease != (domain.Hash{})) {
		return store.ErrCorrupt
	}
	return nil
}

func checkRetirementHTTPSource(candidate CaseRetirementCandidate, rows []evidence.OptionalHoldReceipt, now domain.Time) error {
	found := false
	for _, row := range rows {
		if row.Binding.Case != candidate.Case {
			continue
		}
		if found {
			return store.ErrCorrupt
		}
		if e := checkRetirementSourceRelease(row.State, row.SHA, row.At, candidate.HTTPRelease, now); e != nil {
			return e
		}
		found = true
	}
	if found != (candidate.HTTPRelease != (domain.Hash{})) {
		return store.ErrCorrupt
	}
	return nil
}

// checkRetirementSourceRelease は対象元の現在解除hashと時計を確認する。
func checkRetirementSourceRelease(state string, sha domain.Hash, at domain.Time, expected domain.Hash, now domain.Time) error {
	if expected == (domain.Hash{}) || sha != expected || state != "released" {
		return store.ErrCorrupt
	}
	if at <= 0 || now < at {
		return evidence.ErrRetirementClock
	}
	return nil
}
