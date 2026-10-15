// HTTP元予約の回収候補を既存サイト制御列へ先行登録し、解除正本の不在判定を署名へ束縛する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const optionalHoldRetirementCollection = "optional_hold_retirement"
const optionalHoldRetirementSchema = "optional-http-hold-retirement-registration-v1"

type optionalHoldRetirementRegistration struct {
	Schema      string         `json:"schema"`
	Site        domain.ID      `json:"site_id"`
	Fingerprint domain.Hash    `json:"case_hmac"`
	Previous    evidence.Event `json:"previous_index"`
	Next        evidence.Event `json:"next_index"`
}

func (v optionalHoldRetirementRegistration) candidate() evidence.OptionalHoldRetirementCandidate {
	return evidence.OptionalHoldRetirementCandidate{Previous: v.Previous, Next: v.Next}
}

func decodeOptionalHoldRetirementRegistration(key string, raw json.RawMessage) (optionalHoldRetirementRegistration, error) {
	var v optionalHoldRetirementRegistration
	if len(raw) > 128<<10 || strictjson.Decode(raw, &v) != nil {
		return v, store.ErrCorrupt
	}
	if v.Schema != optionalHoldRetirementSchema || v.Site == (domain.ID{}) || v.Fingerprint == (domain.Hash{}) || key != v.Fingerprint.String() {
		return v, store.ErrCorrupt
	}
	return v, nil
}

// validateOptionalHoldRetirementRegistration は回収候補の削除/置換を禁止する。署名は現在サイト鍵で別途照合する。
func validateOptionalHoldRetirementRegistration(key string, old, next json.RawMessage) error {
	if len(old) != 0 {
		return store.ErrCorrupt
	}
	_, err := decodeOptionalHoldRetirementRegistration(key, next)
	return err
}

func optionalHoldRetirementRegistrations(state store.ControlState, site siteState) (map[domain.Hash]optionalHoldRetirementRegistration, error) {
	result := map[domain.Hash]optionalHoldRetirementRegistration{}
	prefix := optionalHoldRetirementCollection + ":"
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		v, err := decodeOptionalHoldRetirementRegistration(strings.TrimPrefix(name, prefix), row.Value)
		if err != nil {
			return nil, err
		}
		if row.Expires != nil || v.Site != site.ID || site.MinimumReader < evidence.OptionalHoldRetirementReader {
			return nil, store.ErrCorrupt
		}
		result[v.Fingerprint] = v
	}
	return result, nil
}

// verifyOptionalHoldRetirementRegistration は前後索引署名と元解除を現在案件回収登録へ照合する。
func verifyOptionalHoldRetirementRegistration(v optionalHoldRetirementRegistration, original caseRetirementRegistration, key ed25519.PublicKey, now domain.Time) (evidence.OptionalHoldRetirementDescription, error) {
	desc, err := evidence.VerifyOptionalHoldRetirementCandidate(v.Site, key, v.candidate())
	if err != nil {
		return desc, err
	}
	if !matchesOptionalRetirementOriginal(desc, v, original) {
		return desc, store.ErrCorrupt
	}
	intent, err := disclosure.VerifyCaseRetirementIntent(original.Event, v.Fingerprint, key)
	if err != nil {
		return desc, err
	}
	if intent.HTTPRelease == (domain.Hash{}) || desc.Release != intent.HTTPRelease || desc.At < intent.At {
		return desc, store.ErrCorrupt
	}
	if now < desc.At {
		return desc, evidence.ErrRetirementClock
	}
	return desc, nil
}

func matchesOptionalRetirementOriginal(desc evidence.OptionalHoldRetirementDescription, v optionalHoldRetirementRegistration, original caseRetirementRegistration) bool {
	return desc.Fingerprint == v.Fingerprint && original.Site == v.Site && original.Fingerprint == v.Fingerprint && desc.Registration == original.Event.EventSHA
}

// inspectOptionalHoldRetirementRegistry は現在サイトにある全回収候補を変更前に署名/時計照合する。
func inspectOptionalHoldRetirementRegistry(state store.ControlState, site siteState, key ed25519.PublicKey, now domain.Time) error {
	rows, err := optionalHoldRetirementRegistrations(state, site)
	if err != nil {
		return err
	}
	originals, err := caseRetirementRegistrations(state, site)
	if err != nil {
		return err
	}
	for hash, row := range rows {
		original, found := originals[hash]
		if !found {
			return store.ErrCorrupt
		}
		if _, err := verifyOptionalHoldRetirementRegistration(row, original, key, now); err != nil {
			return err
		}
	}
	return nil
}
