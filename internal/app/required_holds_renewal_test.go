// 実署名原本と元台帳で旧期限後の承認済み延長・再送・再起動/GC保護を検証する。
package app

import (
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"reflect"
	"testing"
	"time"
)

func TestRequiredOriginalRenewalAfterDeadlineAndRestart(t *testing.T) {
	f, h, path, b, rows, now := requiredHoldsFixture(t)
	journals := map[uint64]*evidence.Journal{20231114: f.journal}
	original, e := h.Reserve(b, rows, journals, now)
	if e != nil {
		t.Fatal(e)
	}
	approval := RequiredHoldApproval{Revision: b.Revision + 2, At: b.Until - 1}
	until := b.Until + domain.Time(24*time.Hour)
	at := b.Until + 1
	renewed, e := h.Renew(original, approval, until, journals, at)
	if e != nil || renewed.State != "active" || renewed.Binding.Until != until || renewed.Binding.Revision != b.Revision || renewed.Sequence <= original.Sequence {
		t.Fatal(renewed, e)
	}
	if n, e := f.journal.PruneRequired(at, f.selectIdentity, h.Held, nil); e != nil || n != 0 {
		t.Fatal("renewed originals collected", n, e)
	}
	before := retirementFiles(t, path)
	if _, e = h.Renew(original, approval, until, nil, at); e == nil {
		t.Fatal("renewal replay accepted missing original sources")
	}
	replay, e := h.Renew(original, approval, until, journals, at)
	if e != nil || !sameRequiredHoldReceipt(replay, renewed) || !reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("renewal replay wrote history", e)
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, true)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	replay, e = reopened.Renew(original, approval, until, journals, at)
	if e != nil || !sameRequiredHoldReceipt(replay, renewed) {
		t.Fatal("restart renewal replay", e)
	}
	inspection, e := InspectRequiredOriginalHolds(path, f.owner, 10, f.key)
	if e != nil || inspection.MinimumReader != 47 {
		t.Fatal("renewal reader not carried", inspection, e)
	}
	if len(inspection.Renewals) != 1 || !sameRequiredHoldReceipt(inspection.Renewals[0].Original, original) || inspection.Renewals[0].Approval != approval || !sameRequiredHoldReceipt(inspection.Renewals[0].Current, renewed) {
		t.Fatal("inspection renewal proof", inspection.Renewals)
	}
	proof, exists, e := reopened.RenewalReceipt(b.Case)
	if e != nil || !exists {
		t.Fatal(exists, e)
	}
	proof.Original.Postings[0].Identity.ProposalSHA[0] ^= 1
	again, exists, e := reopened.RenewalReceipt(b.Case)
	if e != nil || !exists || !sameRequiredHoldReceipt(again.Original, original) {
		t.Fatal("proof aliases source metadata", e)
	}
	copied, e := reopened.Fetch(renewed, journals, at)
	if e != nil || len(copied) != 1 {
		t.Fatal("renewed fetch", e)
	}
	final, e := reopened.Release(renewed, at+1)
	if e != nil {
		t.Fatal(e)
	}
	active, found, e := reopened.LastActiveReceipt(b.Case)
	if e != nil || !found || !sameRequiredHoldReceipt(active, renewed) {
		t.Fatal("last active reference lost", e)
	}
	initial, found, e := reopened.OriginalReceipt(b.Case)
	if e != nil || !found || !sameRequiredHoldReceipt(initial, original) {
		t.Fatal("first intent reference replaced", e)
	}
	if _, e = reopened.Renew(original, approval, until, journals, at+2); e == nil {
		t.Fatal("released reservation renewed")
	}
	if n, e := f.journal.PruneRequired(at+2, f.selectIdentity, reopened.Held, nil); e != nil || n != 2 {
		t.Fatal("released originals not reclaimed", final, n, e)
	}
}

func TestRequiredOriginalRenewalSignedHistoryRefusesSubstitution(t *testing.T) {
	for _, kind := range []string{"repeated_approval", "changed_scope", "wrong_case_cas"} {
		t.Run(kind, func(t *testing.T) {
			f, h, path, b, rows, now := requiredHoldsFixture(t)
			journals := map[uint64]*evidence.Journal{20231114: f.journal}
			original, e := h.Reserve(b, rows, journals, now)
			if e != nil {
				t.Fatal(e)
			}
			approval := RequiredHoldApproval{Revision: b.Revision + 2, At: now}
			renewed, e := h.Renew(original, approval, b.Until+domain.Time(time.Hour), journals, now)
			if e != nil {
				t.Fatal(e)
			}
			next := renewed.Binding
			next.Until += domain.Time(time.Hour)
			if kind != "repeated_approval" {
				approval.Revision++
			}
			if kind == "changed_scope" {
				next.From++
			}
			expectedSHA := renewed.SHA
			if kind == "wrong_case_cas" {
				expectedSHA[0] ^= 1
			}
			_, result := h.journal.Append(domain.NewID(), "checkpoint", now, func(src evidence.Source) ([]byte, error) {
				return json.Marshal(requiredHoldPayload{Schema: "required-original-hold-v2", Owner: src.Owner, Day: domain.U64(src.Subkey), Sequence: domain.U64(src.Seq), Board: f.owner, At: now, Action: "renew", Binding: &next, ExpectedSequence: renewed.Sequence, ExpectedSHA: expectedSHA, Postings: renewed.Postings, Approval: &approval})
			})
			if result.Status != store.Durable {
				t.Fatal("invalid test did not produce signed history", result)
			}
			if e = h.Close(); e != nil {
				t.Fatal(e)
			}
			before := retirementFiles(t, path)
			if _, e = InspectRequiredOriginalHolds(path, f.owner, 10, f.key); e == nil {
				t.Fatal("signed invalid renewal accepted by check")
			}
			if opened, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, true); e == nil {
				opened.Close()
				t.Fatal("signed invalid renewal accepted by open")
			}
			if !reflect.DeepEqual(before, retirementFiles(t, path)) {
				t.Fatal("invalid signed history was repaired")
			}
		})
	}
}

func TestRequiredOriginalRenewalInvalidApprovalAndSource(t *testing.T) {
	f, h, path, b, rows, now := requiredHoldsFixture(t)
	journals := map[uint64]*evidence.Journal{20231114: f.journal}
	original, e := h.Reserve(b, rows, journals, now)
	if e != nil {
		t.Fatal(e)
	}
	approval := RequiredHoldApproval{Revision: b.Revision + 2, At: now}
	until := b.Until + domain.Time(time.Hour)
	before := retirementFiles(t, path)
	for name, a := range map[string]RequiredHoldApproval{
		"expired":            {Revision: approval.Revision, At: b.Until},
		"before_reservation": {Revision: approval.Revision, At: now - 1},
		"future":             {Revision: approval.Revision, At: now + 1},
		"old_revision":       {Revision: b.Revision, At: now},
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := h.Renew(original, a, until, journals, now); e == nil {
				t.Fatal("invalid approval accepted")
			}
		})
	}
	for _, target := range []domain.Time{b.Until, now, approval.At + domain.Time(180*24*time.Hour) + 1} {
		if _, e := h.Renew(original, approval, target, journals, now); e == nil {
			t.Fatal("invalid deadline accepted")
		}
	}
	if _, e = h.Renew(original, approval, until, nil, now); e == nil {
		t.Fatal("missing originals recreated")
	}
	if _, e = h.Renew(original, approval, until, journals, now-1); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("clock rollback accepted", e)
	}
	if !reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("failed renewal changed holder")
	}
}

func TestRequiredOriginalRenewalInterleavedCasesAndApprovalOrder(t *testing.T) {
	f, h, path, b, rows, now := requiredHoldsFixture(t)
	journals := map[uint64]*evidence.Journal{20231114: f.journal}
	first, e := h.Reserve(b, rows, journals, now)
	if e != nil {
		t.Fatal(e)
	}
	b2 := b
	b2.Case = domain.NewID()
	if _, e = h.Reserve(b2, rows, journals, now); e != nil {
		t.Fatal(e)
	}
	a := RequiredHoldApproval{Revision: b.Revision + 2, At: now}
	renewed, e := h.Renew(first, a, b.Until+domain.Time(time.Hour), journals, now)
	if e != nil || renewed.Sequence != first.Sequence+2 {
		t.Fatal("global sequence treated as per-case next", e)
	}
	before := retirementFiles(t, path)
	if _, e = h.Renew(renewed, a, renewed.Binding.Until+domain.Time(time.Hour), journals, now); e == nil {
		t.Fatal("same approval used twice")
	}
	a2 := a
	a2.Revision++
	second, e := h.Renew(renewed, a2, renewed.Binding.Until+domain.Time(time.Hour), journals, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Renew(first, a, renewed.Binding.Until, journals, now); e == nil {
		t.Fatal("old renewal replay skipped newer change")
	}
	if reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("second renewal not durable")
	}
	if _, e = h.Fetch(second, journals, now); e != nil {
		t.Fatal(e)
	}
}
