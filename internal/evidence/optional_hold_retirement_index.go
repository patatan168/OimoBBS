// 回収対応索引の署名payloadと、一件追加/認可対象一件除去の集合遷移を照合する。
package evidence

import (
	"encoding/json"
	"slices"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// decodeOptionalHoldIndexPayload は現行v2の完全型だけを読み、回収参照を検査する。
func decodeOptionalHoldIndexPayload(body []byte, saved *optionalHoldIndexSaved) error {
	var p optionalHoldRetirementIndexPayload
	if err := strictjson.Decode(body, &p); err != nil {
		return err
	}
	if p.Schema != "optional-http-hold-index-v2" {
		return store.ErrCorrupt
	}
	saved.payload = optionalHoldIndexPayload{p.Owner, p.Subkey, p.Schema, p.Site, p.Sequence, p.At, p.Cases}
	saved.retirement = p.Retirement
	return nil
}

func optionalRetirementIndexPayload(p optionalHoldIndexPayload, retirement *optionalHoldIndexRetirement) optionalHoldRetirementIndexPayload {
	return optionalHoldRetirementIndexPayload{p.Owner, p.Subkey, p.Schema, p.Site, p.Sequence, p.At, p.Cases, retirement}
}

// marshalOptionalHoldIndexPayload は現行v2のnil回収欄も明示する。
func marshalOptionalHoldIndexPayload(p optionalHoldIndexPayload, retirement *optionalHoldIndexRetirement) ([]byte, error) {
	return json.Marshal(optionalRetirementIndexPayload(p, retirement))
}

// validOptionalHoldIndexSchema は現行v2の有界現存集合と回収参照を検査する。
func validOptionalHoldIndexSchema(v optionalHoldIndexSaved) bool {
	p := v.payload
	if p.Schema != "optional-http-hold-index-v2" || p.Sequence < 1 {
		return false
	}
	return validOptionalHoldIndexRetirement(v.retirement, p.Cases)
}

func validOptionalHoldIndexRetirement(r *optionalHoldIndexRetirement, cases []domain.ID) bool {
	if r == nil {
		return true
	}
	return r.Case != (domain.ID{}) && r.Fingerprint != (domain.Hash{}) && r.Release != (domain.Hash{}) && r.Registration != (domain.Hash{}) && !slices.Contains(cases, r.Case)
}

// validateOptionalHoldIndexMembership は除去対象以外の脱落/追加混在と形式の差替えを拒否する。
func validateOptionalHoldIndexMembership(old, next optionalHoldIndexSaved) error {
	if old.payload.Schema == "optional-http-hold-index-v2" && next.payload.Schema != old.payload.Schema {
		return store.ErrCorrupt
	}
	if next.retirement != nil {
		if !slices.Contains(old.payload.Cases, next.retirement.Case) || len(next.payload.Cases) != len(old.payload.Cases)-1 {
			return store.ErrCorrupt
		}
		return checkOptionalHoldIndexSubset(next.payload.Cases, old.payload.Cases)
	}
	if len(next.payload.Cases) != len(old.payload.Cases)+1 {
		return store.ErrCorrupt
	}
	return checkOptionalHoldIndexSubset(old.payload.Cases, next.payload.Cases)
}

func checkOptionalHoldIndexSubset(subset, superset []domain.ID) error {
	for _, id := range subset {
		if !slices.Contains(superset, id) {
			return store.ErrCorrupt
		}
	}
	return nil
}
