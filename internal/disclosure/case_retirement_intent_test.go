// 私有情報なしの回収署名と不正一覧/変更元の拒否を検査する。耐久保存/再起動はsite台帳の製品試験へ置く。
package disclosure

import (
	"bytes"
	"context"
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRetirementIntentPrivateSignatureWithoutFileChanges(t *testing.T) {
	s, candidate, at := retirementInventoryFixture(t)
	before := requiredInspectionFiles(t, s.root)
	intent, event, e := s.BuildCaseRetirementIntent(t.Context(), candidate, nil, nil, at)
	if e != nil || intent.Head != candidate.Head || intent.Revision != candidate.Revision {
		t.Fatal(intent, e)
	}
	loaded, e := s.VerifyCaseRetirementIntent(event, intent.Fingerprint)
	if e != nil || !reflect.DeepEqual(loaded, intent) {
		t.Fatal("signature lost fixed fields", e)
	}
	if _, e = s.VerifyCaseRetirementIntent(event, s.CaseRetirementFingerprint(domain.NewID())); e == nil {
		t.Fatal("signature reused for another case")
	}
	checkRetirementIntentPrivacy(t, s, candidate, intent)
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("building signature changed case files")
	}
}

func checkRetirementIntentPrivacy(t *testing.T, s *Store, candidate CaseRetirementCandidate, intent CaseRetirementIntent) {
	t.Helper()
	raw, e := json.Marshal(intent)
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.Get(candidate.Case)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{candidate.Case.String(), c.Creator.String(), c.Scope.Board.String(), c.Number, c.Reason, "PRIVATE_BODY", "SECRET_CREDENTIAL", "case_id", "actor_id", "scope", "requesting_organization"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("intent retained private data", secret)
		}
	}
}

func checkRetirementIntentSourceBinding(t *testing.T, s *Store, candidate CaseRetirementCandidate, required []app.RequiredHoldReceipt, optional []evidence.OptionalHoldReceipt, at time.Time) {
	t.Helper()
	before := requiredInspectionFiles(t, s.root)
	intent, event, e := s.BuildCaseRetirementIntent(t.Context(), candidate, required, optional, at)
	if e != nil {
		t.Fatal("actual source release not prepared", e)
	}
	verified, e := s.VerifyCaseRetirementIntent(event, intent.Fingerprint)
	if e != nil || verified.RequiredRelease != candidate.RequiredRelease || verified.HTTPRelease != candidate.HTTPRelease {
		t.Fatal("signed intent lost release hashes", e)
	}
	if _, _, e = s.BuildCaseRetirementIntent(t.Context(), candidate, nil, nil, at); e == nil {
		t.Fatal("intent bypassed fresh source checks")
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("source verification changed case files")
	}
	if e = s.ReclaimCaseRetirement(t.Context(), candidate.Case, event, 51, nil, nil, at); e == nil {
		t.Fatal("physical removal bypassed fresh source release")
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("missing source removed case files")
	}
	if e = s.ReclaimCaseRetirement(t.Context(), candidate.Case, event, 51, required, optional, at); e != nil {
		t.Fatal("actual released sources could not reclaim metadata", e)
	}
	checkRetiredCaseDirectoryAbsent(t, s.root, candidate.Case)
}

func TestRetirementIntentRejectsSignedInvalidLists(t *testing.T) {
	for _, damage := range []string{"path", "duplicate", "sha", "missing-current", "clock", "unknown-field"} {
		t.Run(damage, func(t *testing.T) {
			s, candidate, at := retirementInventoryFixture(t)
			intent, _, e := s.BuildCaseRetirementIntent(t.Context(), candidate, nil, nil, at)
			if e != nil {
				t.Fatal(e)
			}
			raw := damageRetirementIntentPayload(t, intent, damage)
			event, e := evidence.Seal(evidence.Source{Owner: intent.Owner, Seq: 1}, intent.Owner, "receipt", raw, domain.Hash{}, 10, s.key)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.VerifyCaseRetirementIntent(event, intent.Fingerprint); e == nil {
				t.Fatal("signed invalid intent accepted", damage)
			}
		})
	}
}

func damageRetirementIntentPayload(t *testing.T, intent CaseRetirementIntent, damage string) []byte {
	t.Helper()
	switch damage {
	case "path":
		intent.Files[0].Name = "control/../control/" + filepath.Base(intent.Files[0].Name)
	case "duplicate":
		intent.Files[1] = intent.Files[0]
	case "sha":
		intent.Files[0].SHA = domain.Hash{}
	case "missing-current":
		intent.Files = intent.Files[:1]
	case "clock":
		intent.At = intent.EligibleAt - 1
	}
	raw, e := json.Marshal(intent)
	if e != nil {
		t.Fatal(e)
	}
	if damage == "unknown-field" {
		raw = append(raw[:len(raw)-1], []byte(`,"unapproved_field":"private"}`)...)
	}
	return raw
}

func TestRetirementIntentRejectsContextAndChangedCandidate(t *testing.T) {
	s, candidate, at := retirementInventoryFixture(t)
	before := requiredInspectionFiles(t, s.root)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, e := s.BuildCaseRetirementIntent(cancelled, candidate, nil, nil, at); e == nil {
		t.Fatal("cancelled build accepted")
	}
	candidate.Head[0] ^= 1
	if _, _, e := s.BuildCaseRetirementIntent(t.Context(), candidate, nil, nil, at); e == nil {
		t.Fatal("changed candidate accepted")
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("refused build changed case files")
	}
}

func TestRetirementIntentRejectsOtherCaseClockWithoutChanges(t *testing.T) {
	s, candidate, at := retirementInventoryFixture(t)
	c, e := s.Get(candidate.Case)
	if e != nil {
		t.Fatal(e)
	}
	input := Case{Number: "future-clock-case", Reason: "fixture", Scope: c.Scope}
	if _, e = s.Create(input, c.Creator, `"evidence:new"`, "future-clock-create", at.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	before := requiredInspectionFiles(t, s.root)
	if _, _, e = s.BuildCaseRetirementIntent(t.Context(), candidate, nil, nil, at); e != ErrExpired {
		t.Fatal("other case clock floor ignored", e)
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("clock refusal changed case files")
	}
}
