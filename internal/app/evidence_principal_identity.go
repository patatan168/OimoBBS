// 保存済み資格から主体の提出項目を取り出し、鍵の用途と未記録項目を区別する。
package app

import (
	"encoding/json"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
)

// projectPrincipalIdentity は検証済みcaptureの主体HMACと資格ID/版だけを取り出す。
// Token.Rate.KeyIDは別用途の鍵なので主体鍵IDとして転記しない。
func projectPrincipalIdentity(capture map[string]json.RawMessage) (map[string]any, error) {
	var token *postcapture.TokenEvidence
	var cap *postcapture.CapEvidence
	var status *string
	for key, target := range map[string]any{"token": &token, "cap": &cap, "token_validation": &status} {
		if raw, found := capture[key]; found {
			if e := json.Unmarshal(raw, target); e != nil {
				return nil, e
			}
		}
	}
	out := map[string]any{"anon_subject_hmac": nil, "hmac_key_id": nil, "cap_id": nil, "cap_revision": nil, "token_validation": nil}
	missing, e := projectAnonymousIdentity(out, token, status)
	if e != nil {
		return nil, e
	}
	if status == nil {
		missing = append(missing, evidence.MissingField{Field: "token_validation", Reason: "not_recorded_in_capture"})
	} else {
		out["token_validation"] = *status
	}
	if cap != nil {
		out["cap_id"], out["cap_revision"] = cap.ID, cap.Revision
	} else {
		reason := "not_recorded_in_capture"
		if _, found := capture["cap"]; found {
			reason = "not_authenticated"
		}
		missing = append(missing, evidence.MissingField{Field: "cap_id", Reason: reason}, evidence.MissingField{Field: "cap_revision", Reason: reason})
	}
	out["missing_fields"] = missing
	return out, nil
}

// projectAnonymousIdentity はvalidと保存された主体だけを提出し、未検証主体を拒否する。
// 鍵IDは現行captureに保存されていないため、現在設定から推定しない。
func projectAnonymousIdentity(out map[string]any, token *postcapture.TokenEvidence, status *string) ([]evidence.MissingField, error) {
	missing := []evidence.MissingField{{Field: "hmac_key_id", Reason: "subject_key_id_not_recorded"}}
	if token != nil {
		if status == nil || *status != "valid" {
			return nil, ErrEvidenceGap
		}
		out["anon_subject_hmac"] = token.Subject
		return missing, nil
	}
	if status != nil && *status == "valid" {
		return nil, ErrEvidenceGap
	}
	reason := "not_recorded_in_capture"
	if status != nil {
		reason = *status
	}
	return append(missing, evidence.MissingField{Field: "anon_subject_hmac", Reason: reason}), nil
}
