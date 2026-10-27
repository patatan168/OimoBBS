// 案件の署名参照と元所有者の最新予約・直後の解除を照合し、私有集合を独立所有で返す。
package evidence

import (
	"encoding/json"
	"slices"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// OptionalHoldReferences は所有排他内の起動/回収検査へ渡す、予約metadataの検査/一時回収保護窓口。
// callback内でだけ使用し、別goroutineへ持ち出したり保存/原本取得へ使用しない。
type OptionalHoldReferences interface {
	OptionalHoldReceipts() ([]OptionalHoldReceipt, error)
	CheckOptionalHoldReceipt(OptionalHoldReceipt) (OptionalHoldReceipt, error)
	CheckOptionalHoldRelease(OptionalHoldReceipt) error
	ProtectOptionalHoldRenewal(OptionalHoldReceipt, OptionalHoldBinding, domain.Time) error
}

type optionalHoldReferences struct{ source *OptionalStore }

func (v optionalHoldReferences) OptionalHoldReceipts() ([]OptionalHoldReceipt, error) {
	return v.source.optionalHoldReceipts()
}

func (v optionalHoldReferences) CheckOptionalHoldReceipt(reference OptionalHoldReceipt) (OptionalHoldReceipt, error) {
	return v.source.checkOptionalHoldReceipt(reference)
}

// optionalHoldReceipt は本人情報を含まない元予約参照を独立所有で構成する。
func (s *OptionalStore) optionalHoldReceipt(v optionalHoldSaved) OptionalHoldReceipt {
	b := v.payload.Binding
	b.Operations = slices.Clone(b.Operations)
	return OptionalHoldReceipt{s.site, b, v.payload.Sequence, v.event.EventSHA, v.payload.At, v.payload.State, slices.Clone(v.payload.Items)}
}

// OptionalHoldReceipts は元所有排他内の最新予約集合を案件ID順に返す。元期限に関係なく解除照合へ使う。
// 本文・IP・署名payloadを返さず、参照の期限/状態を開示認可として扱わない。
func (s *OptionalStore) OptionalHoldReceipts() ([]OptionalHoldReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.optionalHoldReceipts()
}

// optionalHoldReceipts は既に所有排他を確保した巡回の最新metadataを返す。
func (s *OptionalStore) optionalHoldReceipts() ([]OptionalHoldReceipt, error) {
	if s.closed || s.holdsStopped {
		return nil, store.ErrIncomplete
	}
	rows := make([]OptionalHoldReceipt, 0, len(s.holds))
	for _, v := range s.holds {
		rows = append(rows, s.optionalHoldReceipt(v))
	}
	slices.SortFunc(rows, func(a, b OptionalHoldReceipt) int {
		if a.Binding.Case.String() < b.Binding.Case.String() {
			return -1
		}
		if a.Binding.Case == b.Binding.Case {
			return 0
		}
		return 1
	})
	return rows, nil
}

// CheckOptionalHoldReceipt は信頼済み案件参照に対する最新元予約の一致または署名で連続した直後を照合する。
// 古い元正本・同じseqの差替え・範囲/対象差替えを拒否する。二段以上の未証明の進行はErrIncomplete。
// active/releasedのmetadataを返すだけで、期限超過・解除後の原本取得を許可しない。
func (s *OptionalStore) CheckOptionalHoldReceipt(reference OptionalHoldReceipt) (OptionalHoldReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkOptionalHoldReceipt(reference)
}

// checkOptionalHoldReceipt は既に所有排他を確保した巡回で連続性を照合する。
func (s *OptionalStore) checkOptionalHoldReceipt(reference OptionalHoldReceipt) (OptionalHoldReceipt, error) {
	if s.closed || s.holdsStopped {
		return OptionalHoldReceipt{}, store.ErrIncomplete
	}
	v, exists := s.holds[reference.Binding.Case]
	if !exists || reference.Site != s.site || reference.Sequence == 0 || reference.SHA == (domain.Hash{}) || reference.State != "active" {
		return OptionalHoldReceipt{}, store.ErrCorrupt
	}
	current := s.optionalHoldReceipt(v)
	if e := validateOptionalHoldReferenceNext(reference, current, v.event.PreviousSHA); e != nil {
		return OptionalHoldReceipt{}, e
	}
	return current, nil
}

// validateOptionalHoldReferenceNext は元署名の直前hashと案件の固定参照を結び、seq差だけでは進行を認めない。
func validateOptionalHoldReferenceNext(reference, current OptionalHoldReceipt, previous domain.Hash) error {
	if current.Sequence < reference.Sequence {
		return store.ErrCorrupt
	}
	if current.Sequence == reference.Sequence {
		left, _ := json.Marshal(reference)
		right, _ := json.Marshal(current)
		if string(left) != string(right) {
			return store.ErrCorrupt
		}
		return nil
	}
	if !sameOptionalHoldScope(reference.Binding, current.Binding) || !sameOptionalHoldItems(reference.Items, current.Items) || current.Binding.Revision < reference.Binding.Revision || current.Binding.Until < reference.Binding.Until || current.At < reference.At {
		return store.ErrCorrupt
	}
	if current.Sequence-reference.Sequence != 1 {
		return store.ErrIncomplete
	}
	if previous != reference.SHA {
		return store.ErrCorrupt
	}
	return nil
}

// CheckOptionalHoldRelease は信頼済み案件解除参照と現在元解除正本の全一致を要求する。
// 元解除は終端なのでactiveへの巻戻し/別hash/seq/解除正本欠落を拒否する。
func (s *OptionalStore) CheckOptionalHoldRelease(reference OptionalHoldReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkOptionalHoldRelease(reference)
}

// checkOptionalHoldRelease は既に所有排他を保持した起動検査で終端解除を照合する。
func (s *OptionalStore) checkOptionalHoldRelease(reference OptionalHoldReceipt) error {
	if s.closed || s.holdsStopped {
		return store.ErrIncomplete
	}
	v, found := s.holds[reference.Binding.Case]
	if !found || reference.Site != s.site || reference.State != "released" || v.payload.State != "released" {
		return store.ErrCorrupt
	}
	left, _ := json.Marshal(reference)
	right, _ := json.Marshal(s.optionalHoldReceipt(v))
	if string(left) != string(right) {
		return store.ErrCorrupt
	}
	return nil
}

func (v optionalHoldReferences) CheckOptionalHoldRelease(reference OptionalHoldReceipt) error {
	return v.source.checkOptionalHoldRelease(reference)
}
