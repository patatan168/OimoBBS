// 期限内に署名された案件延長intentから固定原本のleaseをCAS更新する。
package evidence

import (
	"context"
	"math"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// RenewOptionalHold は元所有排他内で旧参照と原本を照合して延長をSyncする。
// 呼出元は先行署名済み案件intent・現在認可・容量枠を検査し、その要求時刻をauthorizedAtへ渡す。
// 期限内の承認に限って期限後の再開を許可するが、回収済み原本を復活させない。
func (s *OptionalStore) RenewOptionalHold(ctx context.Context, original OptionalHoldReceipt, b OptionalHoldBinding, authorizedAt domain.Time, now time.Time) (OptionalHoldReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.holdsStopped {
		return OptionalHoldReceipt{}, store.ErrIncomplete
	}
	if e := ctx.Err(); e != nil {
		return OptionalHoldReceipt{}, e
	}
	at := max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano()))
	if !s.validOptionalRenewal(original, b, authorizedAt, at) {
		return OptionalHoldReceipt{}, ErrOptionalQueryScope
	}
	current, e := s.checkOptionalHoldReceipt(original)
	if e != nil {
		return current, e
	}
	if current.State != "active" {
		return current, store.ErrIncomplete
	}
	unchanged := current.Sequence != original.Sequence
	if unchanged && (current.Binding.Revision != b.Revision || current.Binding.Until != b.Until || current.At < authorizedAt) {
		return current, store.ErrIncomplete
	}
	for _, item := range current.Items {
		if _, e = s.optionalHoldEntry(item); e != nil {
			return current, e
		}
	}
	if unchanged {
		return current, nil
	}
	if current.Sequence == domain.U64(math.MaxUint64) {
		return current, store.ErrCorrupt
	}
	b.Operations = slices.Clone(b.Operations)
	p := optionalHoldPayload{Schema: "optional-http-hold-v1", Owner: optionalHoldOwner(s.site), Sequence: current.Sequence + 1, Site: s.site, At: at, State: "active", Binding: b, Items: slices.Clone(current.Items)}
	if e = s.saveOptionalHold(p, current.SHA); e != nil {
		return current, e
	}
	return s.optionalHoldReceipt(s.holds[b.Case]), nil
}

// validOptionalRenewal は承認時刻/新期限/単調版と固定範囲を検査する。
func (s *OptionalStore) validOptionalRenewal(original OptionalHoldReceipt, b OptionalHoldBinding, approved, at domain.Time) bool {
	return at >= s.floor && at >= approved && at < b.Until && validOptionalHoldBinding(b, approved) && approved >= original.At && approved < original.Binding.Until && b.Until > original.Binding.Until && b.Revision > original.Binding.Revision && sameOptionalHoldScope(original.Binding, b)
}
