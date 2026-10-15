// 案件延長intentと元の旧CAS/承認/現在参照を、復旧や原本回収より前に横断照合する。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// CheckRequiredCaseRenewal は元履歴で署名/CAS検査済みの延長証明を現在案件へ束縛する。
// 元の現在性・原本/copyの物理存在と開示認可は別に検査する。
func CheckRequiredCaseRenewal(row RequiredCaseInspection, receipt app.RequiredHoldReceipt, proof *app.RequiredHoldRenewalReceipt) error {
	c := row.Current
	x := c.RequiredExtension
	if x == nil {
		if proof != nil {
			return store.ErrCorrupt
		}
		return CheckRequiredCaseReservation(row, receipt)
	}
	if x.State == "pending" && requiredPendingOriginalCurrent(*x, receipt) {
		return checkRequiredPendingOriginal(row, receipt, proof)
	}
	if proof == nil {
		return store.ErrIncomplete
	}
	if e := checkRequiredExtensionProof(*x, *proof, proof.Current.At); e != nil {
		return e
	}
	if e := checkRequiredRenewalCurrent(receipt, *proof); e != nil {
		return e
	}
	row, e := requiredRenewalInspectionReference(row, *proof)
	if e != nil {
		return e
	}
	return checkRequiredCaseReservationMetadata(row, receipt)
}

// requiredPendingOriginalCurrent は更新前のactiveまたは取消後の旧予約解除を識別する。
func requiredPendingOriginalCurrent(x RequiredHoldExtension, r app.RequiredHoldReceipt) bool {
	return r.State == "active" && sameRequiredReceipt(x.Original, r) || r.State == "released" && sameRequiredReservationIdentity(x.Original, r)
}

// checkRequiredPendingOriginal は元更新前でも直前の確認済み承認を省略せず照合する。
func checkRequiredPendingOriginal(row RequiredCaseInspection, r app.RequiredHoldReceipt, p *app.RequiredHoldRenewalReceipt) error {
	if row.ConfirmedExtension == nil {
		if p != nil {
			return store.ErrCorrupt
		}
		return checkRequiredCaseReservationMetadata(row, r)
	}
	if p == nil {
		return store.ErrIncomplete
	}
	if e := checkRequiredExtensionProof(*row.ConfirmedExtension, *p, p.Current.At); e != nil {
		return e
	}
	if e := checkRequiredRenewalCurrent(r, *p); e != nil {
		return e
	}
	return checkRequiredCaseReservationMetadata(row, r)
}

// checkRequiredRenewalCurrent は解除行と直前active行の固定集合対応を検査する。
func checkRequiredRenewalCurrent(r app.RequiredHoldReceipt, p app.RequiredHoldRenewalReceipt) error {
	if r.State == "active" && !sameRequiredReceipt(r, p.Current) {
		return store.ErrCorrupt
	}
	if r.State == "released" && !sameRequiredReservationIdentity(r, p.Current) {
		return store.ErrCorrupt
	}
	return nil
}

// requiredRenewalInspectionReference は未反映の予約参照だけを非変更の照合用に置き換える。
func requiredRenewalInspectionReference(row RequiredCaseInspection, p app.RequiredHoldRenewalReceipt) (RequiredCaseInspection, error) {
	c := row.Current
	if c.Required == nil {
		return row, store.ErrCorrupt
	}
	if sameRequiredReceipt(c.Required.Reservation, p.Current) {
		return row, nil
	}
	if !requiredExtensionPending(c) || !sameRequiredReceipt(c.Required.Reservation, c.RequiredExtension.Original) || c.Required.Released != nil {
		return row, store.ErrCorrupt
	}
	h := *c.Required
	h.Reservation = p.Current
	c.Required = &h
	row.Current = c
	return row, nil
}

// CheckRequiredCaseReservationsWithRenewals は全案件/元集合に延長証明の因果対応を追加して検査する。
func CheckRequiredCaseReservationsWithRenewals(rows []RequiredCaseInspection, sources []app.RequiredHoldReceipt, renewals []app.RequiredHoldRenewalReceipt) error {
	if len(rows) > MaxCases || len(sources) > MaxCases || len(renewals) > MaxCases {
		return ErrLimit
	}
	byCase, e := requiredInspectionByCase(rows)
	if e != nil {
		return e
	}
	proofs := map[domain.ID]app.RequiredHoldRenewalReceipt{}
	for _, p := range renewals {
		id := p.Current.Binding.Case
		if _, exists := proofs[id]; exists {
			return store.ErrCorrupt
		}
		if _, exists := byCase[id]; !exists {
			return store.ErrCorrupt
		}
		proofs[id] = p
	}
	return checkRequiredRenewalCollections(rows, sources, byCase, proofs)
}

// checkRequiredRenewalCollections は重複・孤立証明・元欠落を含め全集合を双方向に検査する。
func checkRequiredRenewalCollections(rows []RequiredCaseInspection, sources []app.RequiredHoldReceipt, byCase map[domain.ID]RequiredCaseInspection, proofs map[domain.ID]app.RequiredHoldRenewalReceipt) error {
	if len(rows) > MaxCases || len(sources) > MaxCases {
		return ErrLimit
	}
	seen := make(map[domain.ID]bool, len(sources))
	for _, r := range sources {
		row, ok := byCase[r.Binding.Case]
		if !ok || seen[r.Binding.Case] {
			return store.ErrCorrupt
		}
		var proof *app.RequiredHoldRenewalReceipt
		if p, ok := proofs[r.Binding.Case]; ok {
			proof = &p
		}
		if e := CheckRequiredCaseRenewal(row, r, proof); e != nil {
			return e
		}
		seen[r.Binding.Case] = true
	}
	return checkRequiredRenewalCoverage(rows, proofs, seen)
}

// checkRequiredRenewalCoverage は案件参照と延長証明に対応する元が欠けていないことを検査する。
func checkRequiredRenewalCoverage(rows []RequiredCaseInspection, proofs map[domain.ID]app.RequiredHoldRenewalReceipt, seen map[domain.ID]bool) error {
	for _, row := range rows {
		if row.Current.Required != nil && !seen[row.Current.ID] {
			return store.ErrCorrupt
		}
	}
	for id := range proofs {
		if !seen[id] {
			return store.ErrCorrupt
		}
	}
	return nil
}
