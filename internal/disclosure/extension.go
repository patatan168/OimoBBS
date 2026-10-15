// 案件期限と元leaseの段階更新を先行署名intentへ束縛する。
package disclosure

import (
	"encoding/json"
	"math"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// HoldExtension はreader44の延長intent。期限確定まで従来の開示期限を維持する。
// Originalは元所有者とのCAS根拠であり、本文・IPを含まない。
type HoldExtension struct {
	Previous  domain.Time                   `json:"previous_until_ns"`
	Until     domain.Time                   `json:"requested_until_ns"`
	Requested domain.Time                   `json:"requested_at_ns"`
	Revision  domain.U64                    `json:"intent_revision"`
	Actor     domain.ID                     `json:"actor_id"`
	State     string                        `json:"state"`
	Original  evidence.OptionalHoldReceipt  `json:"original_reservation"`
	Confirmed *evidence.OptionalHoldReceipt `json:"confirmed_reservation"`
}

// RetentionUntil は先行延長intentで承認された回収期限を返す。開示認可には使わない。
func (c Case) RetentionUntil() domain.Time {
	if c.RequiredExtension != nil && c.RequiredExtension.State == "pending" {
		return c.RequiredExtension.Until
	}
	if c.Extension != nil && c.Extension.State == "pending" {
		return c.Extension.Until
	}
	return c.Until
}

// validateExtension は署名intentの上限・旧期限・確認済み元参照を照合する。
func validateExtension(c Case, at domain.Time) error {
	x := c.Extension
	if x == nil {
		return nil
	}
	if !validExtensionTimes(c, *x, at) || !validExtensionIdentity(c, *x) {
		return store.ErrCorrupt
	}
	original := *c.HTTP
	original.Reservation = &x.Original
	if e := validateHTTPReservationShape(&original); e != nil {
		return e
	}
	b := x.Original.Binding
	if b.Case != c.ID || b.Board != c.Scope.Board || b.From != c.Scope.From || b.To != c.Scope.To || b.Until != x.Previous || b.Revision >= x.Revision || x.Original.At > x.Requested {
		return store.ErrCorrupt
	}
	if x.State == "pending" {
		return validatePendingExtension(c, *x, at)
	}
	return validateConfirmedExtension(c, *x, at)
}

// validatePendingExtension は旧期限を維持し、取消後だけ未反映の元延長参照を採用する。
func validatePendingExtension(c Case, x HoldExtension, at domain.Time) error {
	if x.Confirmed != nil || c.Until != x.Previous {
		return store.ErrCorrupt
	}
	if sameExtensionJSON(c.HTTP.Reservation, &x.Original) {
		return nil
	}
	if (c.State == "closed" || c.State == "releasing") && extensionReceiptMatches(x, *c.HTTP.Reservation, c.Revision, at) {
		return nil
	}
	return store.ErrCorrupt
}

// terminalExtensionMetadata は取消後の元参照/解除記録だけをpending intentのまま許可する。
func terminalExtensionMetadata(c Case, action string) bool {
	return (c.State == "closed" || c.State == "releasing") && (action == "http_hold_reserved" || action == "http_hold_released")
}

// validExtensionTimes は期限内承認と承認時刻からの180日上限を検査する。
func validExtensionTimes(c Case, x HoldExtension, at domain.Time) bool {
	return x.Previous > c.Created && x.Until > x.Previous && x.Requested >= c.Created && x.Requested < x.Previous && x.Requested <= at && x.Requested <= domain.Time(math.MaxInt64-int64(180*24*time.Hour)) && x.Until <= x.Requested+domain.Time(180*24*time.Hour)
}

// validExtensionIdentity は先行署名版/要求者と元参照の存在を検査する。
func validExtensionIdentity(c Case, x HoldExtension) bool {
	return x.Revision > 0 && x.Revision <= c.Revision && x.Actor != (domain.ID{}) && slices.Contains([]string{"pending", "complete"}, x.State) && c.HTTP != nil && c.HTTP.Reservation != nil
}

// validateConfirmedExtension は保存済み確認を保持し、通常の後続元更新も許可する。
func validateConfirmedExtension(c Case, x HoldExtension, at domain.Time) error {
	if x.Confirmed == nil || c.Until < x.Until || !extensionReceiptMatches(x, *x.Confirmed, c.Revision, at) || c.HTTP.Reservation.Sequence < x.Confirmed.Sequence || c.HTTP.Reservation.Binding.Until < x.Until {
		return store.ErrCorrupt
	}
	return nil
}

// extensionReceiptMatches は延長の固定集合と直後更新のmetadataを照合する。
func extensionReceiptMatches(x HoldExtension, r evidence.OptionalHoldReceipt, revision domain.U64, at domain.Time) bool {
	old := x.Original
	b, ob := r.Binding, old.Binding
	return validExtensionReceiptHeader(x, r, at) && sameExtensionScope(b, ob) && b.Until == x.Until && b.Revision >= x.Revision && b.Revision <= revision && slices.Equal(r.Items, old.Items)
}

// validExtensionReceiptHeader は元署名の状態/seq/時刻を承認へ結ぶ。
func validExtensionReceiptHeader(x HoldExtension, r evidence.OptionalHoldReceipt, at domain.Time) bool {
	return r.State == "active" && r.Site == x.Original.Site && r.Sequence == x.Original.Sequence+1 && r.SHA != (domain.Hash{}) && r.At >= x.Requested && r.At <= at
}

// sameExtensionScope は元予約の固定板/期間/操作集合を照合する。
func sameExtensionScope(a, b evidence.OptionalHoldBinding) bool {
	return a.Unbound == b.Unbound && a.Case == b.Case && a.Board == b.Board && a.From == b.From && a.To == b.To && slices.Equal(a.Operations, b.Operations)
}

// sameExtensionJSON は省略可能欄を含む固定metadataの完全一致を検査する。
func sameExtensionJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

// validateExtensionTransition はintent差替え・期限の先行確定・元参照未証明更新を拒否する。
func validateExtensionTransition(old, next Case, action string) error {
	if e := validateRequiredExtensionTransition(old, next, action); e != nil {
		return e
	}
	if sameExtensionJSON(old.Extension, next.Extension) {
		if old.Extension != nil && old.Extension.State == "pending" && (old.Until != next.Until || action != "release" && action != "expire" && action != "cleanup" && !terminalExtensionMetadata(next, action) && !sameExtensionJSON(old.HTTP, next.HTTP)) {
			return store.ErrCorrupt
		}
		return nil
	}
	x := next.Extension
	if action == "extend_intent" {
		if old.Extension != nil && old.Extension.State == "pending" || x == nil || x.State != "pending" || x.Revision != next.Revision || x.Previous != old.Until || next.Until != old.Until || old.HTTP == nil || old.HTTP.Released != nil || old.HTTP.State != "preparing" && old.HTTP.State != "partial" || !sameExtensionFixedHTTP(old.HTTP, next.HTTP) || !sameExtensionJSON(next.HTTP.Reservation, &x.Original) {
			return store.ErrCorrupt
		}
		return nil
	}
	if action != "extend_complete" || old.Extension == nil || old.Extension.State != "pending" || x == nil || x.State != "complete" {
		return store.ErrCorrupt
	}
	expected := *old.Extension
	expected.State = "complete"
	expected.Confirmed = x.Confirmed
	if !sameExtensionJSON(expected, *x) || next.Until != x.Until || old.State != next.State || x.Confirmed == nil || next.HTTP == nil || next.HTTP.Reservation == nil || !sameExtensionJSON(*next.HTTP.Reservation, *x.Confirmed) {
		return store.ErrCorrupt
	}
	return nil
}

// PrepareExtension は期限内の元参照付き未完了案件に延長intentをSyncする。旧期限の開示は延ばさない。
func (s *Store) PrepareExtension(id, actor domain.ID, etag, key, purpose string, until domain.Time, now time.Time) (Case, error) {
	return s.PrepareExtensionWithSource(id, actor, etag, key, purpose, until, now, nil)
}

// PrepareExtensionWithSource は元所有者で照合済みの初回/直後参照をintentと同時に署名する。
// originalがある場合は現在元正本/前hashの検査を呼出元が済ませる。再送は元更新を増やさない。
func (s *Store) PrepareExtensionWithSource(id, actor domain.ID, etag, key, purpose string, until domain.Time, now time.Time, original *evidence.OptionalHoldReceipt) (Case, error) {
	input := struct {
		Purpose string      `json:"purpose"`
		Until   domain.Time `json:"hold_until_ns"`
	}{purpose, until}
	if replay, ok, e := s.Replay(id, actor, "extend_intent", etag, key, input); e != nil {
		return replay, e
	} else if ok {
		current, err := s.Get(id)
		if err != nil {
			return current, err
		}
		if current.Extension == nil || replay.Extension == nil || current.Extension.Revision != replay.Extension.Revision {
			return current, ErrConflict
		}
		return current, nil
	}
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	at := domain.Time(now.UnixNano())
	if c.Extension != nil && c.Extension.State == "pending" || c.HTTP == nil || c.HTTP.Released != nil || c.HTTP.State != "preparing" && c.HTTP.State != "partial" {
		return c, ErrConflict
	}
	if original != nil {
		if e = s.validateExtensionSource(c, *original, now); e != nil {
			return c, e
		}
		h := *c.HTTP
		copy := *original
		copy.Binding.Operations = slices.Clone(copy.Binding.Operations)
		copy.Items = slices.Clone(copy.Items)
		h.Reservation = &copy
		c.HTTP = &h
	}
	if c.HTTP.Reservation == nil {
		return c, ErrConflict
	}
	if until <= c.Until || until > at+domain.Time(180*24*time.Hour) || c.HTTP.Reservation.Binding.Until != c.Until {
		return c, ErrInvalid
	}
	reference := *c.HTTP.Reservation
	reference.Binding.Operations = slices.Clone(reference.Binding.Operations)
	reference.Items = slices.Clone(reference.Items)
	c.Extension = &HoldExtension{Previous: c.Until, Until: until, Requested: at, Revision: c.Revision + 1, Actor: actor, State: "pending", Original: reference}
	return s.append(c, actor, "extend_intent", purpose, nil, etag, key, input, nil, now)
}

// CompleteExtension は信頼済み元所有者の直後署名を照合してから期限と元参照を同時Syncする。
// checkはOriginalからの前hash連続性と現在正本の全一致を元所有者で検査する。
// 元待ちの排他解放/現在認可は呼出元が行う。
func (s *Store) CompleteExtension(id, actor domain.ID, etag string, receipt evidence.OptionalHoldReceipt, now time.Time, check func() error) (Case, error) {
	c, e := s.Get(id)
	if e != nil {
		return c, e
	}
	if c.ETag() != etag {
		return c, ErrRevision
	}
	x := c.Extension
	if x == nil || c.State == "closed" || c.State == "releasing" || check == nil {
		return c, ErrConflict
	}
	if x.State == "complete" {
		if sameExtensionJSON(*x.Confirmed, receipt) {
			return c, nil
		}
		return c, ErrConflict
	}
	last, e := s.lastAudit(id)
	if e != nil {
		return c, e
	}
	at := domain.Time(now.UnixNano())
	if at < last.At || at >= x.Until {
		return c, ErrExpired
	}
	if !extensionReceiptMatches(*x, receipt, c.Revision, at) {
		return c, store.ErrCorrupt
	}
	if e = check(); e != nil {
		return c, e
	}
	confirmed := *x
	confirmed.State = "complete"
	confirmed.Confirmed = &receipt
	h := *c.HTTP
	receipt.Binding.Operations = slices.Clone(receipt.Binding.Operations)
	receipt.Items = slices.Clone(receipt.Items)
	h.Reservation = &receipt
	c.HTTP = &h
	c.Extension = &confirmed
	c.Until = x.Until
	c.Review = x.Until - domain.Time(7*24*time.Hour)
	return s.append(c, actor, "extend_complete", "source_lease_confirmed", nil, "", "", nil, nil, now)
}

// validateExtensionSource は先行未反映参照を固定集合/原期限と初回または直後seqへ結ぶ。
func (s *Store) validateExtensionSource(c Case, reference evidence.OptionalHoldReceipt, now time.Time) error {
	if e := s.validateHTTPReservation(c, reference, now); e != nil {
		return e
	}
	if old := c.HTTP.Reservation; old != nil {
		if sameExtensionJSON(*old, reference) {
			return nil
		}
		return validateTerminalHTTPReferenceNext(*old, reference)
	}
	if reference.Sequence != 1 {
		return store.ErrIncomplete
	}
	return nil
}

// sameExtensionFixedHTTP は参照採用だけを許可し、固定対象と既存解除を維持する。
func sameExtensionFixedHTTP(old, next *HTTPHold) bool {
	if old == nil || next == nil {
		return false
	}
	left, right := *old, *next
	left.Reservation = nil
	right.Reservation = nil
	return sameExtensionJSON(left, right)
}
