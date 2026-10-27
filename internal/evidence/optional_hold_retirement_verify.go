// サイト登録から元所有者を開かず回収候補の署名・集合遷移・解除束縛を検査する。
package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// OptionalHoldRetirementDescription は署名検査済み候補の登録照合用metadata。削除許可を表さない。
type OptionalHoldRetirementDescription struct {
	Case         domain.ID
	Fingerprint  domain.Hash
	Release      domain.Hash
	Registration domain.Hash
	At           domain.Time
	Sequence     domain.U64
}

// VerifyOptionalHoldRetirementCandidate は前後署名と一件除去を検査し、最新サイト登録との照合情報を返す。
// siteの最低reader/現在時計/登録/案件の物理回収完了は呼出元が別途検査する。
func VerifyOptionalHoldRetirementCandidate(site domain.ID, key ed25519.PublicKey, candidate OptionalHoldRetirementCandidate) (OptionalHoldRetirementDescription, error) {
	var result OptionalHoldRetirementDescription
	previous, err := decodeOptionalHoldRetirementIndexEvent(site, key, candidate.Previous)
	if err != nil {
		return result, err
	}
	next, err := decodeOptionalHoldRetirementIndexEvent(site, key, candidate.Next)
	if err != nil {
		return result, err
	}
	if next.retirement == nil || next.payload.Sequence <= previous.payload.Sequence {
		return result, store.ErrCorrupt
	}
	if err := validateOptionalHoldIndexNext(previous, next); err != nil {
		return result, err
	}
	r := next.retirement
	return OptionalHoldRetirementDescription{r.Case, r.Fingerprint, r.Release, r.Registration, next.payload.At, next.payload.Sequence}, nil
}

func decodeOptionalHoldRetirementIndexEvent(site domain.ID, key ed25519.PublicKey, event Event) (optionalHoldIndexSaved, error) {
	raw, err := json.Marshal(event)
	if err != nil {
		return optionalHoldIndexSaved{}, err
	}
	return decodeOptionalHoldIndexSigned(raw, site, key)
}

func decodeOptionalHoldIndexSigned(raw []byte, site domain.ID, key ed25519.PublicKey) (optionalHoldIndexSaved, error) {
	var v optionalHoldIndexSaved
	if len(key) != ed25519.PublicKeySize || site == (domain.ID{}) {
		return v, store.ErrCorrupt
	}
	if err := decodeOptionalHoldIndexEnvelope(raw, site, &v); err != nil {
		return v, err
	}
	body, err := base64.StdEncoding.Strict().DecodeString(v.event.Payload)
	if err != nil {
		return v, store.ErrCorrupt
	}
	if err := decodeOptionalHoldIndexPayload(body, &v); err != nil {
		return v, store.ErrCorrupt
	}
	if !validOptionalHoldIndexSchema(v) || !validOptionalHoldIndexIdentity(v, site) {
		return v, store.ErrCorrupt
	}
	if !validOptionalHoldIndexCases(v.payload.Cases) {
		return v, store.ErrCorrupt
	}
	_, err = Verify(Source{optionalHoldIndexOwner(site), 0, uint64(v.payload.Sequence)}, v.event, v.event.PreviousSHA, 10, key)
	if err != nil {
		return v, store.ErrCorrupt
	}
	return v, nil
}

func decodeOptionalHoldIndexEnvelope(raw []byte, site domain.ID, v *optionalHoldIndexSaved) error {
	if len(raw) > optionalHoldFileLimit || strictjson.Decode(raw, &v.event) != nil || v.event.RecordID != site || v.event.Kind != "checkpoint" {
		return store.ErrCorrupt
	}
	return nil
}

func validOptionalHoldIndexIdentity(v optionalHoldIndexSaved, site domain.ID) bool {
	p := v.payload
	return p.Site == site && p.Owner == optionalHoldIndexOwner(site) && p.Subkey == 0 && p.At > 0 && p.Cases != nil && len(p.Cases) <= MaxOptionalHolds && validOptionalHoldIndexPrevious(v)
}

func validOptionalHoldIndexPrevious(v optionalHoldIndexSaved) bool {
	if v.payload.Sequence == 1 {
		return v.event.PreviousSHA == (domain.Hash{})
	}
	return v.payload.Sequence > 1 && v.event.PreviousSHA != (domain.Hash{})
}

func validOptionalHoldIndexCases(cases []domain.ID) bool {
	for i, id := range cases {
		if id == (domain.ID{}) || i > 0 && cases[i-1].String() >= id.String() {
			return false
		}
	}
	return true
}
