// 実原本/元署名/案件署名を通して延長の承認、旧期限、取消交差と読取り照合を検証する。
package disclosure

import (
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"slices"
	"testing"
	"time"
)

// requiredExtensionFixture は先行案件承認と実元更新の間をテストから操作できるようにする。
func requiredExtensionFixture(t *testing.T) (*Store, *app.RequiredOriginalHolds, *evidence.Journal, Case, domain.ID, time.Time, uint64) {
	t.Helper()
	s, h, j, _, c, actor, _, _, now, day := requiredReservationFixture(t)
	until := domain.Time(now.Add(120 * 24 * time.Hour).UnixNano())
	c, e := s.PrepareRequiredExtension(c.ID, actor, c.ETag(), "extend-required", "原本延長", until, now)
	if e != nil {
		t.Fatal(e)
	}
	return s, h, j, c, actor, now, day
}

// renewRequiredFixture は実所有者の元履歴から検証済み延長証明を取得する。
func renewRequiredFixture(t *testing.T, h *app.RequiredOriginalHolds, j *evidence.Journal, c Case, day uint64, now time.Time) app.RequiredHoldRenewalReceipt {
	t.Helper()
	a, e := c.RequiredExtensionApproval()
	if e != nil {
		t.Fatal(e)
	}
	_, e = h.Renew(c.RequiredExtension.Original, a, c.RequiredExtension.Until, map[uint64]*evidence.Journal{day: j}, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	p, ok, e := h.RenewalReceipt(c.ID)
	if e != nil || !ok {
		t.Fatal(ok, e)
	}
	return p
}

func TestRequiredExtensionOldDeadlineConfirmationAndCopy(t *testing.T) {
	s, h, j, c, actor, now, day := requiredExtensionFixture(t)
	old := c.Until
	if c.RetentionUntil() != c.RequiredExtension.Until || old != c.RequiredExtension.Previous {
		t.Fatal("intent published deadline")
	}
	if e := s.CheckRequiredRenewal(c, c.RequiredExtension.Original, nil); e != nil {
		t.Fatal(e)
	}
	if e := InspectVersion(s.root, s.key, 46); e == nil {
		t.Fatal("reader46 accepted extension")
	}
	if e := InspectVersion(s.root, s.key, 47); e != nil {
		t.Fatal(e)
	}
	if _, e := s.PrepareHold(c.ID, actor, c.ETag(), "again", "保全", nil, now); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	late := time.Unix(0, int64(old+1))
	if e := s.Sweep(late); e != nil {
		t.Fatal(e)
	}
	current, e := s.Get(c.ID)
	if e != nil || current.State != c.State || current.Until != old {
		t.Fatal(current.State, e)
	}
	if _, e = s.AuthorizeState(c.ID, c.ETag(), late); !errors.Is(e, ErrExpired) {
		t.Fatal("old access deadline", e)
	}
	p := renewRequiredFixture(t, h, j, c, day, late)
	if e = s.CheckRequiredRenewal(c, p.Current, nil); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, p.Current, &p); e != nil {
		t.Fatal(e)
	}
	check := func() error {
		_, e := h.Fetch(p.Current, map[uint64]*evidence.Journal{day: j}, domain.Time(late.UnixNano()))
		return e
	}
	c, e = s.CompleteRequiredExtension(c.ID, actor, c.ETag(), p, late, check)
	if e != nil {
		t.Fatal(e)
	}
	if c.Until != p.Current.Binding.Until || c.RequiredExtension.State != "complete" {
		t.Fatal("deadline not confirmed")
	}
	rows, e := h.Fetch(p.Current, map[uint64]*evidence.Journal{day: j}, domain.Time(late.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.ResumeRequiredReserved(c.ID, actor, c.ETag(), rows, p.Current, late, check)
	if e != nil {
		t.Fatal(e)
	}
	released, e := h.Release(p.Current, domain.Time(late.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, late)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, released, &p); e != nil {
		t.Fatal(e)
	}
	if e = InspectVersion(s.root, s.key, 47); e != nil {
		t.Fatal(e)
	}
	rowsInspection, e := InspectRequiredCaseMetadataVersion(s.root, s.key, 47)
	if e != nil {
		t.Fatal(e)
	}
	if e = CheckRequiredCaseReservationsWithRenewals(rowsInspection, []app.RequiredHoldReceipt{released}, []app.RequiredHoldRenewalReceipt{p}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Records(c, late); e != nil {
		t.Fatal(e)
	}
}

func TestRequiredExtensionCancellationDuringSourceCheck(t *testing.T) {
	s, h, j, c, actor, now, day := requiredExtensionFixture(t)
	p := renewRequiredFixture(t, h, j, c, day, now)
	_, e := s.CompleteRequiredExtension(c.ID, actor, c.ETag(), p, now, func() error {
		_, e := s.Release(c.ID, actor, c.ETag(), "cancel", "取消", now)
		return e
	})
	if !errors.Is(e, ErrRevision) {
		t.Fatal("callback cancellation confirmed", e)
	}
	c, e = s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	old := c.Until
	c, e = s.ReconcileRequiredRenewal(c.ID, actor, c.ETag(), p, now)
	if e != nil {
		t.Fatal(e)
	}
	if c.State != "closed" || c.Until != old || c.RequiredExtension.State != "pending" {
		t.Fatal("cancel resurrected case")
	}
	released, e := h.Release(p.Current, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, released, &p); e != nil {
		t.Fatal(e)
	}
	if e = InspectVersion(s.root, s.key, 47); e != nil {
		t.Fatal(e)
	}
}

func TestRequiredExtensionRefusesWrongProofAndMissingSource(t *testing.T) {
	s, h, j, c, actor, now, day := requiredExtensionFixture(t)
	p := renewRequiredFixture(t, h, j, c, day, now)
	bad := p
	bad.Approval.Revision++
	if _, e := s.CompleteRequiredExtension(c.ID, actor, c.ETag(), bad, now, func() error { return nil }); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal(e)
	}
	bad = p
	bad.Original.SHA[0] ^= 1
	if e := s.CheckRequiredRenewal(c, p.Current, &bad); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal(e)
	}
	if _, e := s.CompleteRequiredExtension(c.ID, actor, c.ETag(), p, now, nil); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	rows, e := InspectRequiredCaseMetadataVersion(s.root, s.key, 47)
	if e != nil {
		t.Fatal(e)
	}
	if e = CheckRequiredCaseReservationsWithRenewals(rows, nil, []app.RequiredHoldRenewalReceipt{p}); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal(e)
	}
	if e = CheckRequiredCaseReservationsWithRenewals(rows, []app.RequiredHoldReceipt{p.Current, p.Current}, []app.RequiredHoldRenewalReceipt{p}); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal(e)
	}
	if e = CheckRequiredCaseReservationsWithRenewals(rows, []app.RequiredHoldReceipt{p.Current}, []app.RequiredHoldRenewalReceipt{p, p}); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal(e)
	}
}

func TestRequiredExtensionRestartAndSubsequentApproval(t *testing.T) {
	s, h, j, c, actor, now, day := requiredExtensionFixture(t)
	p := renewRequiredFixture(t, h, j, c, day, now)
	root, key := s.root, slices.Clone(s.key)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := Open(root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e = s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, p.Current, &p); e != nil {
		t.Fatal(e)
	}
	c, e = s.CompleteRequiredExtension(c.ID, actor, c.ETag(), p, now, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	originalETag := c.ETag()
	c, e = s.CompleteRequiredExtension(c.ID, actor, c.ETag(), p, now, func() error { return nil })
	if e != nil || c.ETag() != originalETag {
		t.Fatal("confirmation replay appended", e)
	}
	replay, e := s.PrepareRequiredExtension(c.ID, actor, c.RequiredExtension.Original.Binding.Case.String(), "extend-required", "原本延長", p.Current.Binding.Until, now)
	// 旧ETagそのものを使わない要求は、同じkeyでも不一致として拒否される。
	if e == nil {
		t.Fatal("wrong request replay accepted", replay)
	}
	nextAt := now.Add(time.Hour)
	nextUntil := c.Until + domain.Time(24*time.Hour)
	c, e = s.PrepareRequiredExtension(c.ID, actor, c.ETag(), "next-extension", "追加延長", nextUntil, nextAt)
	if e != nil {
		t.Fatal(e)
	}
	// 前回の延長証明は、今回の元更新前の旧予約に対して引き続き必要。
	if e = s.CheckRequiredRenewal(c, p.Current, nil); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("previous proof omitted", e)
	}
	badPrevious := p
	badPrevious.Approval.Revision++
	if e = s.CheckRequiredRenewal(c, p.Current, &badPrevious); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("previous approval changed", e)
	}
	if e = s.CheckRequiredRenewal(c, p.Current, &p); e != nil {
		t.Fatal(e)
	}
	next := renewRequiredFixture(t, h, j, c, day, nextAt)
	if e = s.CheckRequiredRenewal(c, next.Current, &p); e == nil {
		t.Fatal("old approval accepted for next update")
	}
	c, e = s.CompleteRequiredExtension(c.ID, actor, c.ETag(), next, nextAt, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = InspectVersion(root, key, 47); e != nil {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, next.Current, &next); e != nil {
		t.Fatal(e)
	}
}

func TestRequiredExtensionExpiryKeepsClosedState(t *testing.T) {
	s, h, j, c, actor, now, day := requiredExtensionFixture(t)
	p := renewRequiredFixture(t, h, j, c, day, now)
	expired := time.Unix(0, int64(c.RequiredExtension.Until))
	if e := s.Sweep(expired); e != nil {
		t.Fatal(e)
	}
	c, e := s.Get(c.ID)
	if e != nil || c.State != "closed" {
		t.Fatal(c.State, e)
	}
	if _, e = s.CompleteRequiredExtension(c.ID, actor, c.ETag(), p, expired, func() error { return nil }); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	c, e = s.ReconcileRequiredRenewal(c.ID, actor, c.ETag(), p, expired)
	if e != nil {
		t.Fatal(e)
	}
	released, e := h.Release(p.Current, domain.Time(expired.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, expired)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, released, &p); e != nil {
		t.Fatal(e)
	}
}

func TestRequiredExtensionCancelledBeforeSourceUpdate(t *testing.T) {
	s, h, _, c, actor, now, _ := requiredExtensionFixture(t)
	original := c.Required.Reservation
	c, e := s.Release(c.ID, actor, c.ETag(), "cancel-unadvanced", "取消", now)
	if e != nil {
		t.Fatal(e)
	}
	released, e := h.Release(original, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, released, nil); e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, released, nil); e != nil {
		t.Fatal(e)
	}
	if e = InspectVersion(s.root, s.key, 47); e != nil {
		t.Fatal(e)
	}
}

func TestRequiredExtensionCancelledAfterUnreflectedSourceRelease(t *testing.T) {
	s, h, j, c, actor, now, day := requiredExtensionFixture(t)
	p := renewRequiredFixture(t, h, j, c, day, now)
	c, e := s.Release(c.ID, actor, c.ETag(), "cancel-updated", "取消", now)
	if e != nil {
		t.Fatal(e)
	}
	released, e := h.Release(p.Current, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, released, &p); e != nil {
		t.Fatal(e)
	}
	c, e = s.ReconcileRequiredRenewal(c.ID, actor, c.ETag(), p, now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CheckRequiredRenewal(c, released, &p); e != nil {
		t.Fatal(e)
	}
}

func TestRequiredExtensionCancellationAfterOldDeadline(t *testing.T) {
	s, h, _, c, actor, _, _ := requiredExtensionFixture(t)
	original := c.Required.Reservation
	late := time.Unix(0, int64(c.Until+1))
	if _, e := s.AuthorizeState(c.ID, c.ETag(), late); !errors.Is(e, ErrExpired) {
		t.Fatal("expired access permitted", e)
	}
	if _, e := s.Release(c.ID, actor, "stale", "cancel-stale", "取消", late); !errors.Is(e, ErrRevision) {
		t.Fatal(e)
	}
	c, e := s.Release(c.ID, actor, c.ETag(), "cancel-late", "取消", late)
	if e != nil {
		t.Fatal(e)
	}
	released, e := h.Release(original, domain.Time(late.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, late)
	if e != nil {
		t.Fatal(e)
	}
	if c.State != "closed" {
		t.Fatal(c.State)
	}
	if e = s.CheckRequiredRenewal(c, released, nil); e != nil {
		t.Fatal(e)
	}
}

func TestRequiredExtensionIntentActorBoundToSignedAudit(t *testing.T) {
	s, _, _, c, _, _, _ := requiredExtensionFixture(t)
	a, e := s.lastAudit(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	a.Actor = domain.NewID()
	if e = validateAudit(c.ID, a); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("actor mismatch accepted", e)
	}
	a.Case.RequiredExtension = nil
	if e = validateAudit(c.ID, a); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("intent without approval accepted", e)
	}
}

func TestRequiredExtensionUnreflectedReferenceAtomicIntent(t *testing.T) {
	s, h, j, _, c, actor, r, _, now, day := requiredReservationPreparedFixture(t)
	before := c.Revision
	until := c.Until + domain.Time(24*time.Hour)
	bad := r
	bad.Binding.Thread++
	if _, e := s.PrepareRequiredExtensionWithSource(c.ID, actor, c.ETag(), "bad-scope", "延長", until, now, &bad); e == nil {
		t.Fatal("different source scope accepted")
	}
	current, e := s.Get(c.ID)
	if e != nil || current.Revision != before || current.Required != nil {
		t.Fatal("bad source changed case", e)
	}
	etag := c.ETag()
	c, e = s.PrepareRequiredExtensionWithSource(c.ID, actor, etag, "atomic-extension", "延長", until, now, &r)
	if e != nil {
		t.Fatal(e)
	}
	if c.Revision != before+1 || c.Required == nil || !sameRequiredReceipt(c.Required.Reservation, r) {
		t.Fatal("source adoption and intent were not atomic")
	}
	p := renewRequiredFixture(t, h, j, c, day, now)
	c, e = s.CompleteRequiredExtension(c.ID, actor, c.ETag(), p, now, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	replay, e := s.PrepareRequiredExtension(c.ID, actor, etag, "atomic-extension", "延長", until, now)
	if e != nil || replay.ETag() != c.ETag() {
		t.Fatal("original request CAS replay failed", e)
	}
	if e = InspectVersion(s.root, s.key, 47); e != nil {
		t.Fatal(e)
	}
}
