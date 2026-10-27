// 案件の固定原本集合と元予約参照を署名履歴の各段階で照合する。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"slices"
	"time"
)

// validateRequiredSourceCase は固定案件/原本集合と元参照を署名時刻へ束縛する。
func validateRequiredSourceCase(c Case, at domain.Time) error {
	if c.Required == nil {
		return nil
	}
	r := c.Required.Reservation
	if e := app.ValidateRequiredHoldReceipt(r); e != nil {
		return e
	}
	if !requiredReferenceMatchesCase(c, r, at) {
		return store.ErrCorrupt
	}
	if e := requiredItemsMatchReceipt(c.Items, r); e != nil {
		return e
	}
	if e := requiredSourceCompletionState(c); e != nil {
		return e
	}
	return validateRequiredSourceRelease(c.Required, at)
}

// requiredSourceCompletionState は未完了copyの解除参照と、完成扱いの欠落hashを拒否する。
func requiredSourceCompletionState(c Case) error {
	if c.Required.Released != nil && c.State != "active" && c.State != "releasing" && c.State != "closed" {
		return store.ErrCorrupt
	}
	if c.State == "active" {
		for _, item := range c.Items {
			if item.State != "held" || item.SHA == (domain.Hash{}) {
				return store.ErrCorrupt
			}
		}
	}
	return nil
}

func requiredReferenceMatchesCase(c Case, r app.RequiredHoldReceipt, at domain.Time) bool {
	return r.State == "active" && r.At >= c.Created && r.At <= at && r.Binding.Revision <= c.Revision && r.Binding.Until <= c.RetentionUntil() && requiredBindingMatchesScope(c, r.Binding)
}

func requiredBindingMatchesScope(c Case, b app.RequiredHoldBinding) bool {
	return b.Case == c.ID && b.Board == c.Scope.Board && b.Thread == c.Scope.Thread && b.From == c.Scope.From && b.To == c.Scope.To
}

// requiredItemsMatchReceipt は署名intentの元ID/hash/期限を参照の全受理集合へ照合する。
func requiredItemsMatchReceipt(items []Item, r app.RequiredHoldReceipt) error {
	if len(items) != len(r.Postings) {
		return store.ErrCorrupt
	}
	expected := make(map[domain.ID]Item, len(items))
	for _, item := range items {
		expected[item.Record] = item
	}
	if len(expected) != len(items) {
		return store.ErrCorrupt
	}
	for _, p := range r.Postings {
		item, exists := expected[p.Identity.ProposalID]
		until := domain.Time(domain.SixMonths(time.Unix(0, int64(p.Identity.Committed))).UnixNano())
		if !exists || item.Source != p.Identity.ProposalSHA || item.Expires != until {
			return store.ErrCorrupt
		}
	}
	return nil
}

func validateRequiredSourceRelease(h *RequiredSourceHold, at domain.Time) error {
	if h.Released == nil {
		return nil
	}
	r, a := *h.Released, h.Reservation
	if e := app.ValidateRequiredHoldReceipt(r); e != nil {
		return e
	}
	if r.State != "released" || r.Sequence <= a.Sequence || r.At < a.At || r.At > at || r.Binding != a.Binding || !slices.Equal(r.Postings, a.Postings) {
		return store.ErrCorrupt
	}
	return nil
}

// validateRequiredSourceTransition は予約/解除参照の削除・差替えと無承認の延長を拒否する。
func validateRequiredSourceTransition(old, next Case, action string) error {
	if old.Required == nil {
		return requiredSourceInitialTransition(old, next, action)
	}
	if e := requiredSourceReservationStable(old, next); e != nil {
		return e
	}
	if old.Required.Released != nil {
		if next.Required.Released == nil || !sameRequiredReceipt(*old.Required.Released, *next.Required.Released) {
			return store.ErrCorrupt
		}
		return nil
	}
	if next.Required.Released != nil && action != "hold_released" {
		return store.ErrCorrupt
	}
	return nil
}

func requiredSourceInitialTransition(old, next Case, action string) error {
	if next.Required == nil {
		if slices.Contains([]string{"hold_reserved", "hold_reconciled", "hold_released", "required_extend_intent"}, action) {
			return store.ErrCorrupt
		}
		return nil
	}
	if next.Required.Released != nil || !requiredSourceInitialAction(old, next, action) {
		return store.ErrCorrupt
	}
	return nil
}

// requiredSourceInitialAction は初回参照の採用を固定対象/終端/先行延長の署名行へ限定する。
func requiredSourceInitialAction(old, next Case, action string) bool {
	terminal := action == "hold_reconciled" && (old.State == "closed" || old.State == "releasing") && sameRequiredFrozenCase(old, next)
	return terminal || requiredExtensionInitialReservation(old, next, action) || action == "hold_reserved" && sameRequiredFixedIntent(old, next)
}

// requiredExtensionInitialReservation は未反映元の採用を同じ先行承認行に限定する。
func requiredExtensionInitialReservation(old, next Case, action string) bool {
	return action == "required_extend_intent" && requiredExtensionPending(next) && sameRequiredFixedIntent(old, next) && sameRequiredReceipt(next.Required.Reservation, next.RequiredExtension.Original)
}

func requiredSourceReservationStable(old, next Case) error {
	if requiredExtensionUpdatesReservation(old, next) {
		return nil
	}
	if next.Required == nil || !sameRequiredReceipt(old.Required.Reservation, next.Required.Reservation) {
		return store.ErrCorrupt
	}
	if old.Required.Released == nil && (old.State == "preparing" || old.State == "partial") && next.Until != old.Until {
		return store.ErrCorrupt
	}
	return nil
}

func sameRequiredFixedIntent(a, b Case) bool {
	if a.State != "preparing" && a.State != "partial" || a.State != b.State || a.Until != b.Until {
		return false
	}
	return sameRequiredFrozenCase(a, b)
}

// sameRequiredFrozenCase は終端参照回復でも状態・期限・固定対象の差替えを許さない。
func sameRequiredFrozenCase(a, b Case) bool {
	return a.ID == b.ID && a.State == b.State && a.Until == b.Until && sameRequiredScope(a.Scope, b.Scope) && slices.Equal(a.Items, b.Items)
}

func sameRequiredScope(a, b Scope) bool {
	return a.Board == b.Board && a.Thread == b.Thread && a.From == b.From && a.To == b.To && slices.Equal(a.Records, b.Records)
}

// RecordRequiredRelease はcopy検証/取消後、現在元で確認済みの署名解除を案件へ保存する。
// 呼出元は元所有列の現在参照/現在認可とreader46を先に検査する。満了後も解除の記録を許す。
func (s *Store) RecordRequiredRelease(id, actor domain.ID, etag string, receipt app.RequiredHoldReceipt, now time.Time) (Case, error) {
	c, e := s.Get(id)
	if e != nil {
		return c, e
	}
	if c.ETag() != etag {
		return c, ErrRevision
	}
	if e = s.readyRequiredRelease(c, now); e != nil {
		return c, e
	}
	if c.Required.Released != nil {
		if !sameRequiredReceipt(*c.Required.Released, receipt) {
			return c, store.ErrCorrupt
		}
		return c, nil
	}
	h := *c.Required
	copy := receipt
	copy.Postings = slices.Clone(receipt.Postings)
	h.Released = &copy
	if e = validateRequiredSourceRelease(&h, domain.Time(now.UnixNano())); e != nil {
		return c, e
	}
	c.Required = &h
	return s.append(c, actor, "hold_released", "durable_required_source_release", nil, "", "", nil, now)
}

// readyRequiredRelease は未完了copyの元解除を拒否し、完成copyを先に照合する。
func (s *Store) readyRequiredRelease(c Case, now time.Time) error {
	if c.Required == nil || c.State == "draft" || c.State == "preparing" || c.State == "partial" {
		return ErrConflict
	}
	if c.State == "active" {
		_, e := s.Records(c, now)
		return e
	}
	return nil
}
