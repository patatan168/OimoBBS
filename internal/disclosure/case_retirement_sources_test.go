// 実元予約の現在解除・未反映参照・欠落/差替えを管理履歴回収候補と照合する。
package disclosure

import (
	"context"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"testing"
	"time"
)

func checkRequiredRetirementSourceVariants(t *testing.T, candidate CaseRetirementCandidate, active, released app.RequiredHoldReceipt, at domain.Time) {
	t.Helper()
	if e := CheckCaseRetirementSources(candidate, []app.RequiredHoldReceipt{released}, nil, at); e != nil {
		t.Fatal(e)
	}
	bad := released
	bad.SHA[0] ^= 1
	for _, rows := range [][]app.RequiredHoldReceipt{nil, {active}, {bad}, {released, released}} {
		if e := CheckCaseRetirementSources(candidate, rows, nil, at); !errors.Is(e, store.ErrCorrupt) {
			t.Fatal("missing/stale/changed/duplicate source accepted", e)
		}
	}
	before := candidate
	before.RequiredRelease = domain.Hash{}
	if e := CheckCaseRetirementSources(before, []app.RequiredHoldReceipt{released}, nil, at); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("unexpected source accepted", e)
	}
}

func TestRetirementSourcesKeepsHTTPReleaseWithoutInitialReference(t *testing.T) {
	s, owner, c, actor, _, _, _, _ := reservedHTTPFixtureWithReference(t, false)
	c, e := s.Release(c.ID, actor, c.ETag(), "retire-http", "cancel", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = owner.ReleaseOptionalHold(context.Background(), c.ID, c.Revision, time.Now()); e != nil {
		t.Fatal(e)
	}
	released, _, e := owner.OptionalHoldReceipt(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordHTTPRelease(c.ID, actor, c.ETag(), released, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	at := domain.Time(c.Closed + caseMetadataRetention)
	plans, e := s.PlanCaseRetirement(time.Unix(0, int64(at)))
	if e != nil || len(plans) != 1 {
		t.Fatal(plans, e)
	}
	checkHTTPRetirementSourceVariants(t, plans[0], released, at)
	checkRetirementIntentSourceBinding(t, s, plans[0], nil, []evidence.OptionalHoldReceipt{released}, time.Unix(0, int64(at)))
}

func checkHTTPRetirementSourceVariants(t *testing.T, candidate CaseRetirementCandidate, released evidence.OptionalHoldReceipt, at domain.Time) {
	t.Helper()
	if candidate.HTTPRelease != released.SHA {
		t.Fatal("release without initial reference lost")
	}
	if e := CheckCaseRetirementSources(candidate, nil, []evidence.OptionalHoldReceipt{released}, at); e != nil {
		t.Fatal(e)
	}
	for _, rows := range [][]evidence.OptionalHoldReceipt{nil, {released, released}} {
		if e := CheckCaseRetirementSources(candidate, nil, rows, at); !errors.Is(e, store.ErrCorrupt) {
			t.Fatal("missing/duplicate HTTP source accepted", e)
		}
	}
	before := candidate
	before.HTTPRelease = domain.Hash{}
	if e := CheckCaseRetirementSources(before, nil, []evidence.OptionalHoldReceipt{released}, at); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("unexpected HTTP release accepted", e)
	}
}
