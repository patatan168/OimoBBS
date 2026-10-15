// 実署名原本/予約台帳/GCを使い、コピー失敗中の保持・再起動・解除と不正参照拒否を確認する。
package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func requiredHoldsFixture(t *testing.T) (retirementFixture, *RequiredOriginalHolds, string, RequiredHoldBinding, []AcceptedEvidence, domain.Time) {
	t.Helper()
	f := newRetirementFixture(t)
	path := filepath.Join(filepath.Dir(f.path), "required-holds")
	h, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = h.Close() })
	now := f.until - domain.Time(24*time.Hour)
	if e = h.Initialize(now); e != nil {
		t.Fatal(e)
	}
	rows, e := AcceptedRecords([]*evidence.Journal{f.journal})
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	b := RequiredHoldBinding{Case: domain.NewID(), Revision: 2, Board: f.owner, From: f.identity.Committed - 1, To: f.identity.Committed + 1, Until: f.until + domain.Time(24*time.Hour)}
	return f, h, path, b, rows, now
}

func TestRequiredOriginalHoldProtectsGCAndRestart(t *testing.T) {
	f, h, path, b, rows, now := requiredHoldsFixture(t)
	journals := map[uint64]*evidence.Journal{20231114: f.journal}
	r, e := h.Reserve(b, rows, journals, now)
	if e != nil {
		t.Fatal(e)
	}
	before := retirementFiles(t, path)
	inspection, e := InspectRequiredOriginalHolds(path, f.owner, 10, f.key)
	if e != nil || inspection.Floor != now || len(inspection.Receipts) != 1 || !sameRequiredHoldReceipt(inspection.Receipts[0], r) {
		t.Fatal(inspection, e)
	}
	if !reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("hold inspection changed source")
	}
	if again, e := h.Reserve(b, rows, journals, f.until+1); e != nil || !sameRequiredHoldReceipt(r, again) {
		t.Fatal(again, e)
	}
	if !reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("reservation replay wrote another event")
	}
	if n, e := f.journal.PruneRequired(f.until+1, f.selectIdentity, h.Held, nil); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	h, e = OpenRequiredOriginalHolds(path, f.owner, 10, f.key, true)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	fetched, e := h.Fetch(r, journals, f.until+1)
	if e != nil || !reflect.DeepEqual(fetched, rows) {
		t.Fatal("held originals after normal expiry", e)
	}
	fetched[0].Proposal.Payload[0] ^= 1
	if _, e = h.Fetch(r, journals, f.until+1); e != nil {
		t.Fatal("fetch aliased original", e)
	}
	for name, raw := range retirementFiles(t, path) {
		for _, source := range f.entries {
			if bytes.Contains(raw, source.Payload) || bytes.Contains(raw, []byte(source.Event.Payload)) {
				t.Fatal("private payload in reservation", name)
			}
		}
	}
	released, e := h.Release(r, f.until+2)
	if e != nil || released.State != "released" {
		t.Fatal(released, e)
	}
	if _, e = h.Release(released, f.until+2); e != nil {
		t.Fatal(e)
	}
	if n, e := f.journal.PruneRequired(f.until+2, f.selectIdentity, h.Held, nil); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	if _, e = h.Fetch(r, journals, f.until+3); e == nil {
		t.Fatal("released source fetched")
	}
	if _, e = h.Reserve(b, rows, journals, f.until+3); e == nil {
		t.Fatal("collected source recreated")
	}
}

func TestRequiredOriginalHoldCapacityAndUnknownFiles(t *testing.T) {
	f, h, path, b, rows, now := requiredHoldsFixture(t)
	journals := map[uint64]*evidence.Journal{20231114: f.journal}
	var first RequiredHoldReceipt
	for i := 0; i < MaxRequiredHolds; i++ {
		b.Case = domain.NewID()
		r, e := h.Reserve(b, rows, journals, now)
		if e != nil {
			t.Fatal(i, e)
		}
		if i == 0 {
			first = r
		}
	}
	if _, e := h.Release(first, now); e != nil {
		t.Fatal(e)
	}
	before := retirementFiles(t, path)
	b.Case = domain.NewID()
	if _, e := h.Reserve(b, rows, journals, now); !errors.Is(e, ErrEvidenceSelectionLimit) {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("capacity refusal mutated source")
	}
	if e := h.Close(); e != nil {
		t.Fatal(e)
	}
	unknown := filepath.Join(path, "unrecognized")
	if e := os.WriteFile(unknown, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	before = retirementFiles(t, path)
	if _, e := InspectRequiredOriginalHolds(path, f.owner, 10, f.key); e == nil {
		t.Fatal("inspection ignored unknown file")
	}
	if opened, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, true); e == nil {
		_ = opened.Close()
		t.Fatal("startup ignored unknown file")
	}
	if !reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("unknown-file refusal changed source")
	}
}

func TestRequiredOriginalHoldSignedStaleCASRefused(t *testing.T) {
	f, h, path, b, rows, now := requiredHoldsFixture(t)
	r, e := h.Reserve(b, rows, map[uint64]*evidence.Journal{20231114: f.journal}, now)
	if e != nil {
		t.Fatal(e)
	}
	wrong := r.SHA
	wrong[0] ^= 1
	_, result := h.journal.Append(domain.NewID(), "checkpoint", now, func(src evidence.Source) ([]byte, error) {
		return json.Marshal(requiredHoldPayload{Schema: "required-original-hold-v2", Owner: src.Owner, Day: domain.U64(src.Subkey), Sequence: domain.U64(src.Seq), Board: f.owner, At: now, Action: "release", Binding: &b, ExpectedSequence: r.Sequence, ExpectedSHA: wrong, Postings: r.Postings})
	})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	before := retirementFiles(t, path)
	if _, e = InspectRequiredOriginalHolds(path, f.owner, 10, f.key); e == nil {
		t.Fatal("valid signature hid stale case CAS")
	}
	if opened, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, true); e == nil {
		_ = opened.Close()
		t.Fatal("invalid CAS recovered")
	}
	if !reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("stale CAS refusal modified journal")
	}
}

func TestRequiredOriginalHoldsRefuseUnverifiedBindings(t *testing.T) {
	f, h, path, b, rows, now := requiredHoldsFixture(t)
	journals := map[uint64]*evidence.Journal{20231114: f.journal}
	before := retirementFiles(t, path)
	for _, mutate := range []func(*RequiredHoldBinding, []AcceptedEvidence){
		func(b *RequiredHoldBinding, _ []AcceptedEvidence) { b.Board = domain.NewID() },
		func(b *RequiredHoldBinding, _ []AcceptedEvidence) { b.Thread = 999 },
		func(b *RequiredHoldBinding, _ []AcceptedEvidence) { b.From = b.To },
		func(b *RequiredHoldBinding, _ []AcceptedEvidence) { b.Until = now },
		func(_ *RequiredHoldBinding, r []AcceptedEvidence) { r[0].Operation = domain.NewID() },
		func(_ *RequiredHoldBinding, r []AcceptedEvidence) { r[0].Post++ },
		func(_ *RequiredHoldBinding, r []AcceptedEvidence) { r[0].Proposal.Event.EventSHA[0] ^= 1 },
	} {
		binding, input := b, append([]AcceptedEvidence{}, rows...)
		mutate(&binding, input)
		if _, e := h.Reserve(binding, input, journals, now); e == nil {
			t.Fatal("invalid reservation accepted")
		}
	}
	if _, e := h.Reserve(b, rows, nil, now); e == nil {
		t.Fatal("missing owner accepted")
	}
	if _, e := h.Reserve(b, rows, journals, f.until); e == nil {
		t.Fatal("expired original rescued")
	}
	if !reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("refusal changed hold journal")
	}
	r, e := h.Reserve(b, rows, journals, now)
	if e != nil {
		t.Fatal(e)
	}
	fake := r
	fake.SHA[0] ^= 1
	if _, e = h.Fetch(fake, journals, now); e == nil {
		t.Fatal("forged receipt fetched")
	}
	if _, e = h.Release(fake, now); e == nil {
		t.Fatal("forged receipt released")
	}
	if _, e = h.Held(r.Postings[0].Identity.ProposalID, now-1); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal(e)
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = h.Held(f.identity.ProposalID, now); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal(e)
	}
	if _, e = OpenRequiredOriginalHolds(filepath.Join(path, "missing"), f.owner, 10, f.key, true); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}

func TestRequiredOriginalHoldMultipleCasesAndDeadline(t *testing.T) {
	f, h, _, b, rows, now := requiredHoldsFixture(t)
	journals := map[uint64]*evidence.Journal{20231114: f.journal}
	first, e := h.Reserve(b, rows, journals, now)
	if e != nil {
		t.Fatal(e)
	}
	b.Case = domain.NewID()
	second, e := h.Reserve(b, rows, journals, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Release(first, now); e != nil {
		t.Fatal(e)
	}
	if n, e := f.journal.PruneRequired(f.until+1, f.selectIdentity, h.Held, nil); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	if _, e = h.Fetch(second, journals, b.Until); e == nil {
		t.Fatal("expired hold disclosed")
	}
	if n, e := f.journal.PruneRequired(b.Until, f.selectIdentity, h.Held, nil); e != nil || n != 2 {
		t.Fatal(n, e)
	}
}
