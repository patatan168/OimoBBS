// 元所有者の解除参照を案件へ署名保存し、解除後の古いactive正本への巻戻しを検出できるようにする。
package disclosure

import (
	"encoding/json"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// validateHTTPReleaseShape は元active参照の直後解除を同じ固定範囲/集合へ束縛する。
func validateHTTPReleaseShape(h *HTTPHold) error {
	r := h.Released
	if r == nil {
		return nil
	}
	a := h.Reservation
	if a == nil {
		return validateInitialHTTPRelease(h, r)
	}
	if r.State != "released" || r.Sequence <= a.Sequence || r.Sequence-a.Sequence != 1 || r.SHA == (domain.Hash{}) || r.Site != a.Site || r.At < a.At {
		return store.ErrCorrupt
	}
	if !sameHTTPReleaseBinding(a.Binding, r.Binding) || !slices.Equal(r.Items, a.Items) {
		return store.ErrCorrupt
	}
	return nil
}

// validateHTTPReleaseTransition は解除参照の削除/差替えと、解除後のactive参照変更を拒否する。
func validateHTTPReleaseTransition(old, next *HTTPHold, action string) error {
	left, _ := json.Marshal(old.Released)
	right, _ := json.Marshal(next.Released)
	if string(left) == string(right) {
		if old.Released != nil {
			a, _ := json.Marshal(old.Reservation)
			b, _ := json.Marshal(next.Reservation)
			if string(a) != string(b) {
				return store.ErrCorrupt
			}
		}
		return nil
	}
	if old.Released != nil || next.Released == nil || action != "http_hold_released" {
		return store.ErrCorrupt
	}
	return validateHTTPReleaseShape(next)
}

// RecordHTTPRelease は元所有者で署名照合した直後解除をreader43案件へ記録する。
// 呼出元は最新元正本と現在案件版を照合し、最低reader43を先に確定する。期限/コピーは変更しない。
func (s *Store) RecordHTTPRelease(id, actor domain.ID, etag string, receipt evidence.OptionalHoldReceipt, now time.Time) (Case, error) {
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
	if receipt.At > domain.Time(now.UnixNano()) || receipt.Binding.Revision > c.Revision {
		return c, store.ErrCorrupt
	}
	copy := receipt
	copy.Binding.Operations = slices.Clone(receipt.Binding.Operations)
	copy.Items = slices.Clone(receipt.Items)
	next := *c.HTTP
	next.Released = &copy
	if e = validateHTTPReleaseShape(&next); e != nil {
		return c, e
	}
	if old := c.HTTP.Released; old != nil {
		left, _ := json.Marshal(old)
		right, _ := json.Marshal(receipt)
		if string(left) != string(right) {
			return c, store.ErrCorrupt
		}
		return c, nil
	}
	c.HTTP = &next
	return s.append(c, actor, "http_hold_released", "durable_http_source_release", nil, "", "", nil, nil, now)
}

// validateInitialHTTPRelease はreader42の参照保存前取消に残った初回解除を固定intentへ束縛する。
func validateInitialHTTPRelease(h *HTTPHold, r *evidence.OptionalHoldReceipt) error {
	if r.State != "released" || r.Sequence != 2 || r.SHA == (domain.Hash{}) || r.Site != h.Site || r.At < h.Captured || r.Binding.Until <= h.Captured || len(r.Items) != len(h.Items) {
		return store.ErrCorrupt
	}
	for i, item := range h.Items {
		ref := r.Items[i]
		if ref.Record != item.Record || ref.SHA != item.Source || ref.Expires != item.Expires || ref.Sequence == 0 || ref.Day == 0 {
			return store.ErrCorrupt
		}
	}
	return nil
}

// sameHTTPReleaseBinding は解除時の案件版以外の固定範囲と操作集合が同じことを照合する。
func sameHTTPReleaseBinding(active, released evidence.OptionalHoldBinding) bool {
	return released.Unbound == active.Unbound && released.Case == active.Case && released.Board == active.Board && released.From == active.From && released.To == active.To && released.Until == active.Until && released.Revision >= active.Revision && slices.Equal(released.Operations, active.Operations)
}

// validateHTTPReleaseCase は解除参照を署名終端案件の範囲/版/監査時刻へ結び、未完了の開示を許可しない。
func validateHTTPReleaseCase(c Case, at domain.Time) error {
	if c.HTTP == nil || c.HTTP.Released == nil {
		return nil
	}
	r := c.HTTP.Released
	if !terminalHTTPReservationCase(c) || r.At > at {
		return store.ErrCorrupt
	}
	if c.HTTP.Reservation == nil && c.State != "closed" && c.State != "releasing" {
		return store.ErrCorrupt
	}
	b := r.Binding
	if b.Case != c.ID || b.Board != c.Scope.Board || b.From != c.Scope.From || b.To != c.Scope.To || b.Until > c.RetentionUntil() || b.Revision > c.Revision {
		return store.ErrCorrupt
	}
	return nil
}
