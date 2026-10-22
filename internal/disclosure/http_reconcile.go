// 完了/取消後も元予約の直後参照を署名し、解除を重ねる前に連続性の証拠を保存する。
package disclosure

import (
	"encoding/json"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// ReconcileHTTPReservation は元所有者で連続性を検証したactive参照を終端案件へ署名保存する。
// コピー/期限/開示状態は変更しない。呼出元は元所有者のCheckOptionalHoldReceiptと現在案件CASを検査する。
func (s *Store) ReconcileHTTPReservation(id, actor domain.ID, etag string, receipt evidence.OptionalHoldReceipt, now time.Time) (Case, error) {
	c, e := s.Get(id)
	if e != nil {
		return c, e
	}
	if c.ETag() != etag {
		return c, ErrRevision
	}
	if !terminalHTTPReservationCase(c) {
		return c, ErrConflict
	}
	if e = validateTerminalHTTPReservation(c, receipt, now); e != nil {
		return c, e
	}
	if old := c.HTTP.Reservation; old != nil {
		left, _ := json.Marshal(old)
		right, _ := json.Marshal(receipt)
		if string(left) == string(right) {
			return c, nil
		}
		if e = validateTerminalHTTPReferenceNext(*old, receipt); e != nil {
			return c, e
		}
	} else if receipt.Sequence != 1 {
		return c, store.ErrIncomplete
	}
	copy := receipt
	copy.Binding.Operations = slices.Clone(receipt.Binding.Operations)
	copy.Items = slices.Clone(receipt.Items)
	c.HTTP.Reservation = &copy
	return s.append(c, actor, "http_hold_reserved", "reconcile_terminal_http_reservation", nil, "", "", nil, now)
}

// validateTerminalHTTPReservation は終端後も署名intentの固定範囲/元集合を維持する。
func validateTerminalHTTPReservation(c Case, receipt evidence.OptionalHoldReceipt, now time.Time) error {
	b := receipt.Binding
	h := *c.HTTP
	if receipt.Site != h.Site || b.Case != c.ID || b.Board != c.Scope.Board || b.From != c.Scope.From || b.To != c.Scope.To || b.Revision > c.Revision || b.Until > c.RetentionUntil() || receipt.At > domain.Time(now.UnixNano()) {
		return store.ErrCorrupt
	}
	h.Reservation = &receipt
	return validateHTTPReservationShape(&h)
}

// validateTerminalHTTPReferenceNext は期限/操作集合を差し替えず直後のactive参照だけを採用する。
func validateTerminalHTTPReferenceNext(old, next evidence.OptionalHoldReceipt) error {
	if next.Sequence <= old.Sequence || next.Sequence-old.Sequence != 1 {
		return store.ErrIncomplete
	}
	if next.Binding.Revision < old.Binding.Revision || next.Binding.Until < old.Binding.Until || next.At < old.At || !slices.Equal(old.Binding.Operations, next.Binding.Operations) || !slices.Equal(old.Items, next.Items) {
		return store.ErrCorrupt
	}
	return nil
}

// terminalHTTPReservationCase は参照後処理を署名済み取消/コピー完了だけに限定する。
func terminalHTTPReservationCase(c Case) bool {
	return c.HTTP != nil && (c.State == "closed" || c.State == "releasing" || c.HTTP.State == "active")
}
