// 実site制御列への署名一覧登録・最低reader・再送/再起動と、変更候補/署名破損の非変更拒否を検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"testing"
	"time"
)

func caseRetirementRegistryFixture(t *testing.T) (Config, *Repository, disclosure.CaseRetirementCandidate) {
	t.Helper()
	cfg, r := adminFixture(t)
	t.Cleanup(func() { _ = r.Close() })
	board, e := r.CreateBoard(t.Context(), "retire", "期限回収")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := r.enableStorageReader(t.Context(), 38, "test_retirement_case_enable"); e != nil {
		t.Fatal(e)
	}
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().Add(-181 * 24 * time.Hour)
	input := disclosure.Case{Number: "PRIVATE_CASE_NUMBER", Reason: "PRIVATE_RETIREMENT_REASON", Scope: disclosure.Scope{Board: board.ID, From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano())}}
	actor := domain.NewID()
	c, e := r.evidenceCases.Create(input, actor, `"evidence:new"`, "registry-create", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.evidenceCases.Release(c.ID, actor, c.ETag(), "registry-close", "cancel", now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	plans, e := r.evidenceCases.PlanCaseRetirement(time.Now())
	if e != nil || len(plans) != 1 {
		t.Fatal(plans, e)
	}
	return cfg, r, plans[0]
}

func registerRetirementForTest(t *testing.T, r *Repository, candidate disclosure.CaseRetirementCandidate) disclosure.CaseRetirementIntent {
	t.Helper()
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	intent, e := r.registerCaseRetirementLocked(t.Context(), candidate, nil, nil, time.Now())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	return intent
}

func TestCaseRetirementRegistrationReopensAndRetainsExactSignature(t *testing.T) {
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	before := requiredStartupFiles(t, cfg.DataDir+"/cases")
	intent := registerRetirementForTest(t, r, candidate)
	row := r.site.State().Rows["case_retirement:"+intent.Fingerprint.String()]
	seq := r.site.State().Seq
	checkCaseRetirementStoredRow(t, r, candidate, row)
	replay := registerRetirementForTest(t, r, candidate)
	if !reflect.DeepEqual(intent, replay) || r.site.State().Seq != seq {
		t.Fatal("replay rewrote intent")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir+"/cases")) {
		t.Fatal("registration modified case files")
	}
	checkCaseRetirementRegisteredRestart(t, cfg, r, candidate, intent, row.Value)
}

func checkCaseRetirementStoredRow(t *testing.T, r *Repository, candidate disclosure.CaseRetirementCandidate, row store.ControlRow) {
	t.Helper()
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	if site.MinimumReader != caseRetirementReader || row.Expires != nil {
		t.Fatal("registration lacked reader or used expiry")
	}
	fingerprint := r.evidenceCases.CaseRetirementFingerprint(candidate.Case)
	v, e := decodeCaseRetirementRegistration(fingerprint.String(), row.Value)
	if e != nil || v.Fingerprint != fingerprint || v.Site != site.ID {
		t.Fatal(v, e)
	}
	intent, e := r.evidenceCases.VerifyCaseRetirementIntent(v.Event, fingerprint)
	if e != nil || intent.Head != candidate.Head || intent.Revision != candidate.Revision {
		t.Fatal("registered signature detached", e)
	}
}

func checkCaseRetirementRegisteredRestart(t *testing.T, cfg Config, r *Repository, candidate disclosure.CaseRetirementCandidate, intent disclosure.CaseRetirementIntent, raw json.RawMessage) {
	t.Helper()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	seq := reopened.site.State().Seq
	row := reopened.site.State().Rows["case_retirement:"+intent.Fingerprint.String()]
	registration, e := decodeCaseRetirementRegistration(intent.Fingerprint.String(), row.Value)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := reopened.evidenceCases.VerifyCaseRetirementIntent(registration.Event, intent.Fingerprint)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(replay, intent) || !reflect.DeepEqual(row.Value, raw) || reopened.site.State().Seq != seq {
		t.Fatal("restart changed registered receipt")
	}
	checkCaseRetirementStoredRow(t, reopened, candidate, row)
}

func TestCaseRetirementRegistrationRejectsStaleAndCancelledBeforeReaderChange(t *testing.T) {
	for _, damage := range []string{"head", "cancel"} {
		t.Run(damage, func(t *testing.T) {
			cfg, r, candidate := caseRetirementRegistryFixture(t)
			before := requiredStartupFiles(t, cfg.DataDir)
			ctx := t.Context()
			if damage == "head" {
				candidate.Head[0] ^= 1
			} else {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			r.optionalHoldLifecycleMu.Lock()
			r.mu.Lock()
			_, e := r.registerCaseRetirementLocked(ctx, candidate, nil, nil, time.Now())
			r.mu.Unlock()
			r.optionalHoldLifecycleMu.Unlock()
			if e == nil {
				t.Fatal("invalid registration accepted")
			}
			if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
				t.Fatal("invalid registration changed storage/reader")
			}
		})
	}
}
