// 取消と元予約Syncが交差した案件へ、最初の署名intentに一致する予約参照を回復する。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"slices"
	"time"
)

// ReconcileRequiredReservation は終端案件だけに初回予約参照を保存する。copyや期限は変更しない。
// 呼出元は同じ元所有列で署名済みOriginalReceiptの現在性を確認する。
func (s *Store) ReconcileRequiredReservation(id, actor domain.ID, etag string, receipt app.RequiredHoldReceipt, now time.Time) (Case, error) {
	c, e := s.Get(id)
	if e != nil {
		return c, e
	}
	if c.ETag() != etag {
		return c, ErrRevision
	}
	if c.Required != nil {
		if !sameRequiredReceipt(c.Required.Reservation, receipt) {
			return c, store.ErrCorrupt
		}
		return c, nil
	}
	if c.State != "closed" && c.State != "releasing" || receipt.State != "active" {
		return c, ErrConflict
	}
	row, e := s.inspectRequiredCaseHistory(id, 50, false)
	if e != nil {
		return c, e
	}
	if e = CheckRequiredCaseReservation(row, receipt); e != nil {
		return c, e
	}
	receipt.Postings = slices.Clone(receipt.Postings)
	c.Required = &RequiredSourceHold{Reservation: receipt}
	return s.append(c, actor, "hold_reconciled", "reconcile_terminal_required_reservation", nil, "", "", nil, now)
}

// CheckRequiredReservation は現在の署名履歴と元参照を変更せず照合する。認可は呼出元が行う。
func (s *Store) CheckRequiredReservation(c Case, receipt app.RequiredHoldReceipt) error {
	row, e := s.inspectRequiredCaseHistory(c.ID, 50, false)
	if e != nil {
		return e
	}
	if row.Current.ETag() != c.ETag() {
		return ErrRevision
	}
	return CheckRequiredCaseReservation(row, receipt)
}

// CheckRequiredRenewal は現在案件の署名履歴と元延長証明を非変更で照合する。
func (s *Store) CheckRequiredRenewal(c Case, receipt app.RequiredHoldReceipt, proof *app.RequiredHoldRenewalReceipt) error {
	row, e := s.inspectRequiredCaseHistory(c.ID, 50, false)
	if e != nil {
		return e
	}
	if row.Current.ETag() != c.ETag() {
		return ErrRevision
	}
	return CheckRequiredCaseRenewal(row, receipt, proof)
}

// ReconcileRequiredRenewal は取消後に更新済み元参照だけを採用し、開示期限やcopyを復活させない。
// 呼出元は同じ元所有列で証明と現在性を検査してから渡す。
func (s *Store) ReconcileRequiredRenewal(id, actor domain.ID, etag string, proof app.RequiredHoldRenewalReceipt, now time.Time) (Case, error) {
	c, e := s.Get(id)
	if e != nil {
		return c, e
	}
	if c.ETag() != etag {
		return c, ErrRevision
	}
	if (c.State != "closed" && c.State != "releasing") || !requiredExtensionPending(c) {
		return c, ErrConflict
	}
	if e = s.CheckRequiredRenewal(c, proof.Current, &proof); e != nil {
		return c, e
	}
	if sameRequiredReceipt(c.Required.Reservation, proof.Current) {
		return c, nil
	}
	h := *c.Required
	h.Reservation = proof.Current
	h.Reservation.Postings = slices.Clone(proof.Current.Postings)
	c.Required = &h
	return s.append(c, actor, "hold_reconciled", "reconcile_terminal_required_renewal", nil, "", "", nil, now)
}
