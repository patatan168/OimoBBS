// 主体HMAC・資格IDの提出と鍵用途の区別、未検証主体の拒否を検査する。
package app

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"testing"
)

func TestPrincipalIdentitySeparatesSubjectAndRateKeys(t *testing.T) {
	subject := domain.Hash{1}
	token := postcapture.TokenEvidence{Subject: subject, Rate: domain.RateKey{Rule: domain.NewID(), KeyID: 7, Subject: domain.Hash{2}, Cost: 1}}
	raw, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	out, e := projectPrincipalIdentity(map[string]json.RawMessage{"token": raw, "token_validation": json.RawMessage(`"valid"`)})
	if e != nil {
		t.Fatal(e)
	}
	if out["anon_subject_hmac"] != subject || out["hmac_key_id"] != nil {
		t.Fatal("admission key used as subject key", out)
	}
	assertPrincipalMissingReason(t, out, "hmac_key_id", "subject_key_id_not_recorded")
}

func assertPrincipalMissingReason(t *testing.T, out map[string]any, key, reason string) {
	t.Helper()
	for _, field := range out["missing_fields"].([]evidence.MissingField) {
		if field.Field == key {
			if field.Reason != reason {
				t.Fatal("wrong missing reason", field)
			}
			return
		}
	}
	t.Fatal("missing reason omitted", key)
}

func TestPrincipalIdentityDoesNotAdoptUnverifiedToken(t *testing.T) {
	token, err := json.Marshal(postcapture.TokenEvidence{Subject: domain.Hash{1}, Rate: domain.RateKey{Rule: domain.NewID(), KeyID: 7, Cost: 1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"absent", "invalid", "not_checked"} {
		t.Run(status, func(t *testing.T) {
			raw, _ := json.Marshal(status)
			if _, e := projectPrincipalIdentity(map[string]json.RawMessage{"token": token, "token_validation": raw}); e != ErrEvidenceGap {
				t.Fatal("unverified token adopted", e)
			}
			out, e := projectPrincipalIdentity(map[string]json.RawMessage{"token": json.RawMessage(`null`), "token_validation": raw})
			if e != nil || out["anon_subject_hmac"] != nil {
				t.Fatal("missing subject invented", e)
			}
			assertPrincipalMissingReason(t, out, "anon_subject_hmac", status)
		})
	}
	if _, e := projectPrincipalIdentity(map[string]json.RawMessage{"token_validation": json.RawMessage(`"valid"`)}); e != ErrEvidenceGap {
		t.Fatal("valid token without stored proof accepted", e)
	}
}

func TestPrincipalIdentityUsesStoredCap(t *testing.T) {
	cap := postcapture.CapEvidence{ID: domain.NewID(), Revision: 1, KeyID: 9, Name: "担当"}
	raw, _ := json.Marshal(cap)
	out, e := projectPrincipalIdentity(map[string]json.RawMessage{"cap": raw})
	if e != nil {
		t.Fatal(e)
	}
	if out["cap_id"] != cap.ID || out["cap_revision"] != cap.Revision {
		t.Fatal("stored cap omitted", out)
	}
	out, e = projectPrincipalIdentity(map[string]json.RawMessage{"cap": json.RawMessage(`null`)})
	if e != nil {
		t.Fatal(e)
	}
	assertPrincipalMissingReason(t, out, "cap_id", "not_authenticated")
	assertPrincipalMissingReason(t, out, "cap_revision", "not_authenticated")
}

func TestPrincipalIdentityLegacyMissingFields(t *testing.T) {
	out, e := projectPrincipalIdentity(map[string]json.RawMessage{})
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"anon_subject_hmac", "token_validation", "cap_id", "cap_revision"} {
		if out[key] != nil {
			t.Fatal("legacy value inferred", key)
		}
		assertPrincipalMissingReason(t, out, key, "not_recorded_in_capture")
	}
}
