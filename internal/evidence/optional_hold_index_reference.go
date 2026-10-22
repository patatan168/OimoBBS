// サイト側の回収登録が現在の署名索引を照合できるよう、所有排他内の参照を返す。
package evidence

import (
	"crypto/ed25519"
	"slices"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// OptionalHoldIndexReferences は起動/回収callbackでだけ使う現在索引の検査窓口。
type OptionalHoldIndexReferences interface{ OptionalHoldIndexEvent() (Event, error) }

// OptionalHoldIndexDescription は署名済み現在索引の照合metadata。案件IDは内部検査だけで使用する。
type OptionalHoldIndexDescription struct {
	Schema   string
	Sequence domain.U64
	At       domain.Time
	SHA      domain.Hash
	Cases    []domain.ID
}

// VerifyOptionalHoldIndexEvent は公開鍵で現在索引を照合し、独立所有の現存集合を返す。
func VerifyOptionalHoldIndexEvent(site domain.ID, key ed25519.PublicKey, event Event) (OptionalHoldIndexDescription, error) {
	v, err := decodeOptionalHoldRetirementIndexEvent(site, key, event)
	if err != nil {
		return OptionalHoldIndexDescription{}, err
	}
	return OptionalHoldIndexDescription{v.payload.Schema, v.payload.Sequence, v.payload.At, v.event.EventSHA, slices.Clone(v.payload.Cases)}, nil
}

func (v optionalHoldReferences) OptionalHoldIndexEvent() (Event, error) {
	if v.source.closed || v.source.holdsStopped || v.source.holdIndex.payload.Sequence == 0 {
		return Event{}, store.ErrIncomplete
	}
	return v.source.holdIndex.event, nil
}
