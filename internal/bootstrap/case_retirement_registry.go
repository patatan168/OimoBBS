// 案件管理履歴回収の固定署名を既存site制御列へ先行登録し、記録欠落を外部fileへ依存させない。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strings"
)

const caseRetirementReader = 51
const caseRetirementRegistrySchema = "case-retirement-registration-v1"

type caseRetirementRegistration struct {
	Schema      string         `json:"schema"`
	Site        domain.ID      `json:"site_id"`
	Fingerprint domain.Hash    `json:"case_hmac"`
	Event       evidence.Event `json:"prepared_receipt"`
}

func decodeCaseRetirementRegistration(key string, raw json.RawMessage) (caseRetirementRegistration, error) {
	var v caseRetirementRegistration
	if len(raw) > 64<<10 || strictjson.Decode(raw, &v) != nil {
		return v, store.ErrCorrupt
	}
	if v.Schema != caseRetirementRegistrySchema || v.Site == (domain.ID{}) || v.Fingerprint == (domain.Hash{}) || key != v.Fingerprint.String() {
		return v, store.ErrCorrupt
	}
	if !validCaseRetirementEnvelope(v) {
		return v, store.ErrCorrupt
	}
	return v, nil
}

func validCaseRetirementEnvelope(v caseRetirementRegistration) bool {
	var owner domain.ID
	copy(owner[:], v.Fingerprint[:16])
	e := v.Event
	return e.Schema == "evidence-v1" && e.Kind == "receipt" && e.RecordID == owner && e.SigningKeyID == 10 && e.PreviousSHA == (domain.Hash{}) && e.EventSHA != (domain.Hash{})
}

// validateCaseRetirementRegistration は固定記録の置換/削除を拒否する。署名は起動検査で専用鍵へ照合する。
func validateCaseRetirementRegistration(key string, old, next json.RawMessage) error {
	if len(old) != 0 {
		return store.ErrCorrupt
	}
	_, e := decodeCaseRetirementRegistration(key, next)
	return e
}

// caseRetirementRegistrations はsite/最低reader/期限なし行へ固定記録を束縛する。
func caseRetirementRegistrations(state store.ControlState, site siteState) (map[domain.Hash]caseRetirementRegistration, error) {
	result := map[domain.Hash]caseRetirementRegistration{}
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "case_retirement:") {
			continue
		}
		v, e := decodeCaseRetirementRegistration(strings.TrimPrefix(name, "case_retirement:"), row.Value)
		if e != nil {
			return nil, e
		}
		if row.Expires != nil || v.Site != site.ID || site.MinimumReader < caseRetirementReader {
			return nil, store.ErrCorrupt
		}
		result[v.Fingerprint] = v
	}
	return result, nil
}

// inspectCaseRetirementRegistry は最初の物理回収より前に全登録の元署名/時計床を非変更検査する。
func inspectCaseRetirementRegistry(state store.ControlState, site siteState, key ed25519.PublicKey, now domain.Time) error {
	rows, e := caseRetirementRegistrations(state, site)
	if e != nil {
		return e
	}
	for fingerprint, row := range rows {
		intent, e := disclosure.VerifyCaseRetirementIntent(row.Event, fingerprint, key)
		if e != nil {
			return e
		}
		if now < intent.At {
			return evidence.ErrRetirementClock
		}
		if e = requireRetirementHTTPActivation(state, site.ID, intent); e != nil {
			return e
		}
	}
	return inspectOptionalHoldRetirementRegistry(state, site, key, now)
}

// requireRetirementHTTPActivation は案件不在でも有効化済み元台帳の欠落を補完させない。
func requireRetirementHTTPActivation(state store.ControlState, site domain.ID, intent disclosure.CaseRetirementIntent) error {
	if intent.HTTPRelease == (domain.Hash{}) {
		return nil
	}
	for _, name := range []string{"optional_http:http", "optional_holds:http"} {
		row, exists := state.Rows[name]
		var activation optionalLogActivation
		if !exists || strictjson.Decode(row.Value, &activation) != nil || activation.Site != site || activation.Phase != "active" || row.Expires != nil {
			return store.ErrCorrupt
		}
	}
	return nil
}
