// 延長intentと確定を実案件/元予約/再起動で検査し、旧期限の開示と新期限の回収を区別する。
package disclosure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func TestExtensionIntentRestartOldDeadlineAndConfirmedCopy(t *testing.T) {
	s, owner, c, actor, _, _, _, key := reservedHTTPFixture(t)
	oldUntil, etag := c.Until, c.ETag()
	oldBytes, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	var old Case
	if e = json.Unmarshal(oldBytes, &old); e != nil {
		t.Fatal(e)
	}
	round, e := json.Marshal(old)
	if e != nil || !bytes.Equal(oldBytes, round) {
		t.Fatal("legacy bytes changed", e)
	}
	target := oldUntil + domain.Time(24*time.Hour)
	c, e = s.PrepareExtension(c.ID, actor, etag, "extension-1", "期間延長", target, time.Now())
	if e != nil || c.Until != oldUntil || c.RetentionUntil() != target || c.Extension.State != "pending" {
		t.Fatal(c, e)
	}
	replay, e := s.PrepareExtension(c.ID, actor, etag, "extension-1", "期間延長", target, time.Now())
	if e != nil || replay.ETag() != c.ETag() {
		t.Fatal("intent replay", replay, e)
	}
	root := s.root
	if _, e = InspectCaseMetadataVersion(root, key, 43); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("reader43 accepted intent", e)
	}
	if _, e = InspectCaseMetadataVersion(root, key, 44); e != nil {
		t.Fatal("reader44 rejected intent", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(root, key)
	if e != nil {
		t.Fatal("pending restart", e)
	}
	defer s.Close()
	cut := time.Unix(0, int64(oldUntil)).Add(time.Minute)
	if e = s.Sweep(cut); e != nil {
		t.Fatal("pending copies swept", e)
	}
	c, e = s.Get(c.ID)
	if e != nil || c.State == "closed" {
		t.Fatal(c, e)
	}
	if _, e = s.Records(c, cut); !errors.Is(e, ErrExpired) {
		t.Fatal("intent advanced disclosure deadline", e)
	}
	b := c.Extension.Original.Binding
	b.Revision = c.Extension.Revision
	b.Until = target
	receipt, e := owner.RenewOptionalHold(context.Background(), c.Extension.Original, b, c.Extension.Requested, cut)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e = owner.CheckOptionalHoldReceipt(c.Extension.Original)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.CompleteExtension(c.ID, actor, c.ETag(), receipt, cut, extensionOwnerCheck(owner, c.Extension.Original, receipt))
	if e != nil || c.Until != target || c.Extension.State != "complete" || c.HTTP.Reservation.SHA != receipt.SHA {
		t.Fatal(c, e)
	}
	same, e := s.PrepareExtension(c.ID, actor, etag, "extension-1", "期間延長", target, cut)
	if e != nil || same.ETag() != c.ETag() {
		t.Fatal("completed request replay", same, e)
	}
	same, e = s.CompleteExtension(c.ID, actor, c.ETag(), receipt, cut, reservationCheck(owner, receipt))
	if e != nil || same.ETag() != c.ETag() {
		t.Fatal("completion replay", same, e)
	}
	rows, e := owner.QueryOptionalHold(context.Background(), c.ID, cut)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	c, e = s.ResumeHTTPReserved(c.ID, actor, c.ETag(), rows, receipt, cut, reservationCheck(owner, receipt))
	if e != nil || c.HTTP.State != "active" {
		t.Fatal("copy after confirmed extension", c, e)
	}
	if rows, e := s.HTTPRecords(c, cut); e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	if e = InspectVersion(root, key, 44); e != nil {
		t.Fatal("confirmed history/artifacts", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(root, key)
	if e != nil {
		t.Fatal("confirmed restart", e)
	}
	defer s.Close()
	c, e = s.Get(c.ID)
	if e != nil || c.Until != target {
		t.Fatal(c, e)
	}
}

func TestExtensionRejectsConflictingIntentAndUnconfirmedLease(t *testing.T) {
	s, owner, c, actor, ref, entries, _, _ := reservedHTTPFixture(t)
	etag := c.ETag()
	target := c.Until + domain.Time(24*time.Hour)
	c, e := s.PrepareExtension(c.ID, actor, etag, "extension-2", "延長", target, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.PrepareExtension(c.ID, actor, etag, "extension-2", "変更", target, time.Now()); !errors.Is(e, ErrConflict) {
		t.Fatal("changed replay accepted", e)
	}
	if _, e = s.Extend(c.ID, actor, c.ETag(), "bypass", "延長", target, time.Now()); !errors.Is(e, ErrConflict) {
		t.Fatal("direct deadline bypass", e)
	}
	if _, e = s.PrepareHTTPHold(c.ID, actor, c.ETag(), "copy-during-extension", "保全", c.HTTP.Site, entries, time.Now()); !errors.Is(e, ErrConflict) {
		t.Fatal("pending intent allowed copy preparation", e)
	}
	if _, e = s.ResumeHTTPReserved(c.ID, actor, c.ETag(), entries, ref, time.Now(), reservationCheck(owner, ref)); !errors.Is(e, ErrConflict) {
		t.Fatal("pending intent allowed copy completion", e)
	}
	called := false
	if _, e = s.CompleteExtension(c.ID, actor, c.ETag(), ref, time.Now(), func() error { called = true; return nil }); !errors.Is(e, store.ErrCorrupt) || called {
		t.Fatal("old lease completed", e, called)
	}
	b := ref.Binding
	b.Until = target
	b.Revision = c.Revision
	if e = owner.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	next, e := owner.CheckOptionalHoldReceipt(ref)
	if e != nil {
		t.Fatal(e)
	}
	failure := errors.New("current owner unavailable")
	if _, e = s.CompleteExtension(c.ID, actor, c.ETag(), next, time.Now(), func() error { return failure }); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	current, e := s.Get(c.ID)
	if e != nil || current.ETag() != c.ETag() || current.Until != ref.Binding.Until {
		t.Fatal("failed confirmation changed case", current, e)
	}
	if _, e = s.CompleteExtension(c.ID, actor, c.ETag(), next, time.Now(), nil); !errors.Is(e, ErrConflict) {
		t.Fatal("missing owner proof accepted", e)
	}
	changed := next
	changed.SHA[0] ^= 1
	if _, e = s.CompleteExtension(c.ID, actor, c.ETag(), changed, time.Now(), reservationCheck(owner, changed)); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("different lease accepted", e)
	}
	if e = s.Sweep(time.Unix(0, int64(target))); e != nil {
		t.Fatal(e)
	}
	expired, e := s.Get(c.ID)
	if e != nil || expired.State != "closed" {
		t.Fatal("pending intent never expired", expired, e)
	}
}

// 元予約が確定後に通常更新されても、過去の延長確認参照を差し替えない。
func TestExtensionConfirmedReferenceSurvivesLaterSourceUpdate(t *testing.T) {
	s, owner, c, actor, _, entries, _, _ := reservedHTTPFixture(t)
	c, e := s.PrepareExtension(c.ID, actor, c.ETag(), "extension-3", "延長", c.Until+domain.Time(24*time.Hour), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	b := c.Extension.Original.Binding
	b.Revision = c.Revision
	b.Until = c.Extension.Until
	if e = owner.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	confirmed, e := owner.CheckOptionalHoldReceipt(c.Extension.Original)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.CompleteExtension(c.ID, actor, c.ETag(), confirmed, time.Now(), reservationCheck(owner, confirmed))
	if e != nil {
		t.Fatal(e)
	}
	b, e = s.HTTPReservationBinding(c, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = owner.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	latest, e := owner.CheckOptionalHoldReceipt(confirmed)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.BindHTTPReservation(c.ID, actor, c.ETag(), latest, time.Now())
	if e != nil || c.Extension.Confirmed.SHA != confirmed.SHA || c.HTTP.Reservation.SHA != latest.SHA {
		t.Fatal(c, e)
	}
}

// 異なる署名操作でintentを差し替えたり期限だけ進めたりできない。
func TestExtensionTransitionRejectsIntentReplacement(t *testing.T) {
	s, _, c, actor, _, _, _, _ := reservedHTTPFixture(t)
	c, e := s.PrepareExtension(c.ID, actor, c.ETag(), "extension-4", "延長", c.Until+domain.Time(24*time.Hour), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	next := c
	x := *c.Extension
	x.Until += domain.Time(time.Hour)
	next.Extension = &x
	if e = validateExtensionTransition(c, next, "query"); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal(e)
	}
	next = c
	next.Until = c.Extension.Until
	if e = validateExtensionTransition(c, next, "extend"); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal(e)
	}
}

// extensionOwnerCheck は元所有者で前hashを含む直後証明と現在正本の全一致を検査する。
func extensionOwnerCheck(owner *evidence.OptionalStore, original, expected evidence.OptionalHoldReceipt) func() error {
	return func() error {
		current, e := owner.CheckOptionalHoldReceipt(original)
		if e != nil {
			return e
		}
		if !sameExtensionJSON(current, expected) {
			return store.ErrIncomplete
		}
		return nil
	}
}

// 参照未保存の初回/直後元更新を延長intentへ同時採用し、要求etagの再送を維持する。
func TestExtensionIntentAdoptsInitialOrImmediateSource(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "immediate"}[bound], func(t *testing.T) {
			s, owner, c, actor, ref, entries, _, _ := reservedHTTPFixtureWithReference(t, bound)
			if bound {
				b, e := s.HTTPReservationBinding(c, time.Now())
				if e != nil {
					t.Fatal(e)
				}
				if e = owner.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
					t.Fatal(e)
				}
				ref, e = owner.CheckOptionalHoldReceipt(ref)
				if e != nil {
					t.Fatal(e)
				}
			}
			etag := c.ETag()
			target := c.Until + domain.Time(24*time.Hour)
			updated, e := s.PrepareExtensionWithSource(c.ID, actor, etag, "adopt-extension", "延長", target, time.Now(), &ref)
			if e != nil || updated.HTTP.Reservation.SHA != ref.SHA || updated.Extension.Original.SHA != ref.SHA {
				t.Fatal(updated, e)
			}
			replay, e := s.PrepareExtension(updated.ID, actor, etag, "adopt-extension", "延長", target, time.Now())
			if e != nil || replay.ETag() != updated.ETag() {
				t.Fatal("original request replay", replay, e)
			}
		})
	}
}

func TestExtensionCancelledAfterLeaseUpdateReconcilesRelease(t *testing.T) {
	s, owner, c, actor, _, _, _, key := reservedHTTPFixture(t)
	c, e := s.PrepareExtension(c.ID, actor, c.ETag(), "cancelled-extension", "延長", c.Until+domain.Time(24*time.Hour), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	oldUntil := c.Until
	b := c.Extension.Original.Binding
	b.Revision = c.Extension.Revision
	b.Until = c.Extension.Until
	renewed, e := owner.RenewOptionalHold(context.Background(), c.Extension.Original, b, c.Extension.Requested, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Release(c.ID, actor, c.ETag(), "cancel-pending-extension", "取消", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	checked, e := owner.CheckOptionalHoldReceipt(c.Extension.Original)
	if e != nil || checked.SHA != renewed.SHA {
		t.Fatal(checked, e)
	}
	c, e = s.ReconcileHTTPReservation(c.ID, actor, c.ETag(), checked, time.Now())
	if e != nil {
		t.Fatal("terminal adoption", e)
	}
	if e = owner.ReleaseOptionalHoldChecked(context.Background(), checked, c.Revision, time.Now()); e != nil {
		t.Fatal(e)
	}
	released, e := owner.CheckOptionalHoldReceipt(checked)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordHTTPRelease(c.ID, actor, c.ETag(), released, time.Now())
	if e != nil || c.State != "closed" || c.Until != oldUntil || c.HTTP.Released.SHA != released.SHA {
		t.Fatal(c, e)
	}
	if _, e = s.CompleteExtension(c.ID, actor, c.ETag(), renewed, time.Now(), extensionOwnerCheck(owner, c.Extension.Original, renewed)); !errors.Is(e, ErrConflict) {
		t.Fatal("cancel revived extension", e)
	}
	root := s.root
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = InspectCaseMetadataVersion(root, key, 44); e != nil {
		t.Fatal("cancelled history", e)
	}
}
