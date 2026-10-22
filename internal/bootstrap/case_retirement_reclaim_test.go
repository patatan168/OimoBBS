// 実site先行登録→案件file回収→製品再起動で固定IDの再出現を拒否し、別案件の保存枠を使えることを検査する。
package bootstrap

import (
	"fmt"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCaseRetirementPhysicalRemovalReopensWithoutResurrectingCaseID(t *testing.T) {
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	intent := registerRetirementForTest(t, r, candidate)
	c, e := r.evidenceCases.Get(candidate.Case)
	if e != nil {
		t.Fatal(e)
	}
	fillRetirementCaseCapacity(t, r, c)
	reclaimRegisteredCaseForTest(t, r, candidate, intent)
	if _, e = os.Lstat(filepath.Join(cfg.DataDir, "cases", candidate.Case.String())); !os.IsNotExist(e) {
		t.Fatal("product case files remained", e)
	}
	checkRetiredCaseCreationRefused(t, r, c)
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	checkRetiredCaseCreationRefused(t, reopened, c)
	checkRetirementSlotReusable(t, reopened, c)
}

func reclaimRegisteredCaseForTest(t *testing.T, r *Repository, candidate disclosure.CaseRetirementCandidate, intent disclosure.CaseRetirementIntent) {
	t.Helper()
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	row := r.site.State().Rows["case_retirement:"+intent.Fingerprint.String()]
	v, e := decodeCaseRetirementRegistration(intent.Fingerprint.String(), row.Value)
	if e != nil {
		t.Fatal(e)
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	if e = r.evidenceCases.ReclaimCaseRetirement(t.Context(), candidate.Case, v.Event, site.MinimumReader, nil, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
}

func checkRetiredCaseCreationRefused(t *testing.T, r *Repository, c disclosure.Case) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	input := disclosure.Case{Number: c.Number, Reason: c.Reason, Scope: c.Scope}
	if _, e := r.evidenceCases.Create(input, c.Creator, `"evidence:new"`, "registry-create", time.Now()); e != disclosure.ErrExpired {
		t.Fatal("retired fixed ID recreated", e)
	}
}

func checkRetirementSlotReusable(t *testing.T, r *Repository, old disclosure.Case) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	input := disclosure.Case{Number: "next-case", Reason: "fixture", Scope: old.Scope}
	c, e := r.evidenceCases.Create(input, old.Creator, `"evidence:new"`, "registry-next", time.Now())
	if e != nil || c.ID == old.ID || c.State != "draft" {
		t.Fatal("reclaimed slot could not admit new case", c, e)
	}
}

func fillRetirementCaseCapacity(t *testing.T, r *Repository, old disclosure.Case) {
	t.Helper()
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	input := disclosure.Case{Number: "capacity-case", Reason: "fixture", Scope: old.Scope}
	for n := 1; n < disclosure.MaxCases; n++ {
		if _, e := r.evidenceCases.Create(input, old.Creator, `"evidence:new"`, fmt.Sprintf("capacity-%d", n), time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := r.evidenceCases.Create(input, old.Creator, `"evidence:new"`, "registry-next", time.Now()); e != disclosure.ErrLimit {
		t.Fatal("fixture did not exhaust case capacity", e)
	}
}
