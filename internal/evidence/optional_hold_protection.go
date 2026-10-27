// 先行署名延長intentを原本の回収復旧/周期回収へ渡す一時metadata保護。
package evidence

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

type optionalHoldProtection struct {
	SHA   domain.Hash
	Until domain.Time
}

// ProtectOptionalHoldRenewal は検査callback内で署名済みintentの新期限を原本GCへ反映する。
// 呼出元は案件署名/版/範囲を検証する。元正本は更新せず、開示期限も延ばさない。
func (v optionalHoldReferences) ProtectOptionalHoldRenewal(original OptionalHoldReceipt, b OptionalHoldBinding, approved domain.Time) error {
	return v.source.protectOptionalHoldRenewal(original, b, approved)
}

// ProtectOptionalHoldRenewal は元所有排他内で先行署名intentの一時回収保護を設定する。
// 署名済み案件intentの検証は呼出元が行う。原本取得/開示や元正本の更新はしない。
func (s *OptionalStore) ProtectOptionalHoldRenewal(original OptionalHoldReceipt, b OptionalHoldBinding, approved domain.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.protectOptionalHoldRenewal(original, b, approved)
}

// protectOptionalHoldRenewal は検査窓口と通常所有排他から同じintent照合を使う。
func (s *OptionalStore) protectOptionalHoldRenewal(original OptionalHoldReceipt, b OptionalHoldBinding, approved domain.Time) error {
	if !validOptionalHoldBinding(b, approved) || approved < original.At || approved >= original.Binding.Until || b.Until <= original.Binding.Until || b.Revision <= original.Binding.Revision || !sameOptionalHoldScope(original.Binding, b) {
		return store.ErrCorrupt
	}
	current, e := s.checkOptionalHoldReceipt(original)
	if e != nil {
		return e
	}
	if current.State != "active" {
		return store.ErrIncomplete
	}
	if current.Sequence != original.Sequence && (current.Binding.Revision != b.Revision || current.Binding.Until != b.Until || current.At < approved) {
		return store.ErrIncomplete
	}
	if s.holdProtections == nil {
		s.holdProtections = map[domain.ID]optionalHoldProtection{}
	}
	s.holdProtections[b.Case] = optionalHoldProtection{current.SHA, b.Until}
	s.rebuildOptionalHoldIndex()
	return nil
}

// optionalHoldUntil は現在の署名正本と一致するintent保護だけを予約期限へ合成する。
func (s *OptionalStore) optionalHoldUntil(v optionalHoldSaved) domain.Time {
	until := v.payload.Binding.Until
	if protection, ok := s.holdProtections[v.payload.Binding.Case]; ok && protection.SHA == v.event.EventSHA {
		until = max(until, protection.Until)
	}
	return until
}
