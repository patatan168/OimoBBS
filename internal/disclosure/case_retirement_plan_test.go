// 実コピーの取消後に180日の境界・時計・最小候補・非変更を検査する。
package disclosure

import (
	"encoding/json"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCaseRetirementPlanAfterActualCopyCleanup(t *testing.T) {
	s, _, input, actor, now, record := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "retire-plan-create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "retire-plan-hold", "preserve", []app.AcceptedEvidence{record}, now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Release(c.ID, actor, c.ETag(), "retire-plan-release", "cancel", now)
	if e != nil {
		t.Fatal(e)
	}
	checkCaseRetirementBoundary(t, s, c)
}

func checkCaseRetirementBoundary(t *testing.T, s *Store, c Case) {
	t.Helper()
	before := requiredInspectionFiles(t, s.root)
	deadline := time.Unix(0, int64(c.Closed+caseMetadataRetention))
	early, e := s.PlanCaseRetirement(deadline.Add(-time.Nanosecond))
	if e != nil || len(early) != 0 {
		t.Fatal("early retirement", early, e)
	}
	result, e := s.PlanCaseRetirement(deadline)
	if e != nil || len(result) != 1 {
		t.Fatal(result, e)
	}
	checkCaseRetirementCandidate(t, s, c, result[0])
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("planning changed private files")
	}
	if _, e = s.PlanCaseRetirement(time.Unix(0, int64(c.Closed)-1)); !errors.Is(e, ErrExpired) {
		t.Fatal("clock floor lost", e)
	}
}

func checkCaseRetirementCandidate(t *testing.T, s *Store, c Case, candidate CaseRetirementCandidate) {
	t.Helper()
	a, event, e := s.lastAuditEvent(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	if candidate.Case != c.ID || candidate.Revision != c.Revision || candidate.Head != event.EventSHA || candidate.Clock != a.At {
		t.Fatal("candidate detached from signed head", candidate)
	}
	raw, e := json.Marshal(candidate)
	if e != nil {
		t.Fatal(e)
	}
	for _, private := range []string{c.Number, c.Reason, "PRIVATE_BODY", "SECRET_CREDENTIAL"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("candidate retained private metadata")
		}
	}
}

func TestCaseRetirementPlanBlocksUnfinishedCopyOrSource(t *testing.T) {
	base := Case{State: "closed", Closed: 1, Items: []Item{{State: "removed"}}, Exports: []Export{{State: "removed"}}}
	for _, damage := range []string{"copy", "export", "required", "http"} {
		t.Run(damage, func(t *testing.T) {
			c := base
			c.Items = append([]Item{}, base.Items...)
			c.Exports = append([]Export{}, base.Exports...)
			damageCaseRetirement(&c, damage)
			_, _, e := planCaseRetirement(Audit{Case: c}, evidence.Event{}, c.Closed+caseMetadataRetention)
			if !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("unfinished retirement accepted", damage, e)
			}
		})
	}
}

func damageCaseRetirement(c *Case, damage string) {
	switch damage {
	case "copy":
		c.Items[0].State = "held"
	case "export":
		c.Exports[0].State = "ready"
	case "required":
		c.Required = &RequiredSourceHold{}
	case "http":
		c.HTTP = &HTTPHold{State: "active"}
	}
}

func TestCaseRetirementPlanRequiresDurableRequiredRelease(t *testing.T) {
	s, source, _, _, c, actor, receipt, _, now, _ := requiredReservationFixture(t)
	c, e := s.Release(c.ID, actor, c.ETag(), "retire-required-release", "cancel", now)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Unix(0, int64(c.Closed+caseMetadataRetention))
	if _, e = s.PlanCaseRetirement(at); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("source reservation skipped", e)
	}
	released, e := source.Release(receipt, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, now)
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.PlanCaseRetirement(at)
	if e != nil || len(result) != 1 {
		t.Fatal(result, e)
	}
	if result[0].RequiredRelease != released.SHA {
		t.Fatal("release proof detached")
	}
	checkCaseRetirementCandidate(t, s, c, result[0])
	checkRequiredRetirementSourceVariants(t, result[0], receipt, released, domain.Time(at.UnixNano()))
	checkRetirementIntentSourceBinding(t, s, result[0], []app.RequiredHoldReceipt{released}, nil, at)
}
