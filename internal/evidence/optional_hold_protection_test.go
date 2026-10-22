// 延長intentの一時保護が期限後/再起動のGCへ先行し、開示を広げず、取消で解除できることを検査する。
package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestOptionalHoldProtectionThroughExpiredLeaseGCAndRestart(t *testing.T) {
	s, key, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	original, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil {
		t.Fatal(e)
	}
	next := b
	next.Revision++
	next.Until += domain.Time(24 * time.Hour)
	approved := domain.Time(now.Add(time.Minute).UnixNano())
	guard := func(v OptionalHoldReferences) error { return v.ProtectOptionalHoldRenewal(original, next, approved) }
	cut := time.Unix(0, int64(b.Until)).Add(time.Minute)
	reserve := func(int64) (func(), error) { return func() {}, nil }
	if n, e := s.SweepReservedChecked(cut, reserve, guard); e != nil || n != 1 {
		t.Fatal("intent did not protect original", n, e)
	}
	if _, e = s.QueryOptionalHold(context.Background(), b.Case, cut); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("protection advanced disclosure lease", e)
	}
	root, site := s.root, s.site
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if e = InspectOptionalStoreChecked(root, site, key, guard); e != nil {
		t.Fatal("protected read-only inspection", e)
	}
	s, e = OpenOptionalStoreChecked(root, site, key, guard)
	if e != nil {
		t.Fatal("protected restart", e)
	}
	defer s.Close()
	renewed, e := s.RenewOptionalHold(context.Background(), original, next, approved, cut)
	if e != nil || renewed.Binding.Until != next.Until {
		t.Fatal("protected late renewal", renewed, e)
	}
	rows, e := s.QueryOptionalHold(context.Background(), b.Case, cut)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	if _, e = s.SweepReservedChecked(cut, reserve, guard); e != nil {
		t.Fatal("confirmed guard", e)
	}
}

func TestOptionalHoldProtectionClearedWhenCaseNoLongerAuthorizesIt(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	defer s.Close()
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	original, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil {
		t.Fatal(e)
	}
	next := b
	next.Revision++
	next.Until += domain.Time(24 * time.Hour)
	approved := domain.Time(now.Add(time.Minute).UnixNano())
	reserve := func(int64) (func(), error) { return func() {}, nil }
	cut := time.Unix(0, int64(b.Until)).Add(time.Minute)
	if _, e = s.SweepReservedChecked(cut, reserve, func(v OptionalHoldReferences) error { return v.ProtectOptionalHoldRenewal(original, next, approved) }); e != nil {
		t.Fatal(e)
	}
	if n, e := s.SweepReservedChecked(cut, reserve, func(OptionalHoldReferences) error { return nil }); e != nil || n != 1 {
		t.Fatal("cancelled intent still pinned source", n, e)
	}
}

func TestOptionalHoldProtectionRejectsLateOrInterveningAuthorization(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	defer s.Close()
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	original, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil {
		t.Fatal(e)
	}
	next := b
	next.Revision++
	next.Until += domain.Time(24 * time.Hour)
	if e = s.ProtectOptionalHoldRenewal(original, next, b.Until); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("expired approval accepted", e)
	}
	interim := b
	interim.Revision++
	if e = s.ReserveOptionalHold(context.Background(), interim, entries, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if e = s.ProtectOptionalHoldRenewal(original, next, domain.Time(now.Add(2*time.Second).UnixNano())); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("intermediate lease skipped", e)
	}
	if len(s.holdProtections) != 0 {
		t.Fatal("rejected protection was installed")
	}
}
