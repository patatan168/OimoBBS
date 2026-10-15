// 元lease延長の期限内承認・期限後再開・原本欠落とCAS/再送を実fileで検査する。
package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestOptionalHoldRenewalAuthorizedBeforeExpiryAndRestart(t *testing.T) {
	s, key, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	original, found, e := s.OptionalHoldReceipt(b.Case)
	if e != nil || !found {
		t.Fatal(found, e)
	}
	next := b
	next.Revision++
	next.Until += domain.Time(24 * time.Hour)
	approved := domain.Time(now.Add(time.Minute).UnixNano())
	cut := time.Unix(0, int64(b.Until)).Add(time.Minute)
	renewed, e := s.RenewOptionalHold(context.Background(), original, next, approved, cut)
	if e != nil || renewed.Sequence != original.Sequence+1 || renewed.Binding.Until != next.Until {
		t.Fatal(renewed, e)
	}
	proof, e := s.CheckOptionalHoldReceipt(original)
	if e != nil || proof.SHA != renewed.SHA {
		t.Fatal(proof, e)
	}
	repeated, e := s.RenewOptionalHold(context.Background(), original, next, approved, cut)
	if e != nil || repeated.SHA != renewed.SHA {
		t.Fatal("duplicate renewal", repeated, e)
	}
	if n, e := s.Sweep(cut); e != nil || n != 1 {
		t.Fatal("renewal did not protect fixed original", n, e)
	}
	rows, e := s.QueryOptionalHold(context.Background(), b.Case, cut)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	root, site := s.root, s.site
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	restarted, e := s.CheckOptionalHoldReceipt(original)
	if e != nil || restarted.SHA != renewed.SHA {
		t.Fatal(restarted, e)
	}
}

func TestOptionalHoldRenewalRejectsLateApprovalAndMissingOriginal(t *testing.T) {
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
	cut := time.Unix(0, int64(b.Until)).Add(time.Minute)
	if _, e = s.RenewOptionalHold(context.Background(), original, next, b.Until, cut); !errors.Is(e, ErrOptionalQueryScope) {
		t.Fatal("late approval accepted", e)
	}
	after, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil || after.SHA != original.SHA {
		t.Fatal(after, e)
	}
	if _, e = s.Sweep(cut); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RenewOptionalHold(context.Background(), original, next, domain.Time(now.Add(time.Minute).UnixNano()), cut); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("collected original resurrected", e)
	}
}

func TestOptionalHoldRenewalRejectsInterveningUpdateAndCandidateResume(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	defer s.Close()
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	original, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil {
		t.Fatal(e)
	}
	interim := b
	interim.Revision++
	if e = s.ReserveOptionalHold(context.Background(), interim, entries, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	next := b
	next.Revision += 2
	next.Until += domain.Time(24 * time.Hour)
	approved := domain.Time(now.Add(2 * time.Second).UnixNano())
	if _, e = s.RenewOptionalHold(context.Background(), original, next, approved, now.Add(3*time.Second)); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("intermediate update skipped", e)
	}
	original, e = s.CheckOptionalHoldReceipt(original)
	if e != nil {
		t.Fatal(e)
	}
	s.checkpoint = func(at string) error {
		if at == "hold:sync" {
			return store.ErrIncomplete
		}
		return nil
	}
	if _, e = s.RenewOptionalHold(context.Background(), original, next, approved, now.Add(3*time.Second)); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal(e)
	}
	s.checkpoint = nil
	if e = s.ReloadOptionalHolds(); e != nil {
		t.Fatal(e)
	}
	resumed, e := s.RenewOptionalHold(context.Background(), original, next, approved, now.Add(4*time.Second))
	if e != nil || resumed.Sequence != original.Sequence+1 {
		t.Fatal("candidate resume", resumed, e)
	}
}

func TestOptionalHoldRenewalReplayChecksStoppedOriginalOwner(t *testing.T) {
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
	approved := domain.Time(now.Add(time.Second).UnixNano())
	renewed, e := s.RenewOptionalHold(context.Background(), original, next, approved, now.Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RenewOptionalHold(context.Background(), original, next, domain.Time(now.Add(3*time.Second).UnixNano()), now.Add(4*time.Second)); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("lease predating intent adopted", e)
	}
	s.journals[uint64(original.Items[0].Day)].stopped = true
	if _, e = s.RenewOptionalHold(context.Background(), original, next, approved, now.Add(3*time.Second)); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("replay skipped stopped source owner", e)
	}
	after, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil || after.SHA != renewed.SHA {
		t.Fatal("rejected replay changed lease", after, e)
	}
}
