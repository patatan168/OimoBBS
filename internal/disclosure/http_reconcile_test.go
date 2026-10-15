// 終端案件での初回/直後参照採用が期限やコピーを復活させず、署名履歴として再起動できることを検査する。
package disclosure

import (
	"context"
	"errors"
	"testing"
	"time"

	"oimobbs/internal/store"
)

func TestHTTPReconcileTerminalFirstOrNextAfterDeadline(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(map[bool]string{false: "first", true: "next"}[bound], func(t *testing.T) {
			s, owner, c, actor, ref, entries, _, key := reservedHTTPFixtureWithReference(t, bound)
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
			c, e := s.Release(c.ID, actor, c.ETag(), "terminal-cancel", "cancel", time.Now())
			if e != nil {
				t.Fatal(e)
			}
			deadline := time.Unix(0, int64(c.Until)).Add(time.Hour)
			updated, e := s.ReconcileHTTPReservation(c.ID, actor, c.ETag(), ref, deadline)
			if e != nil || updated.State != "closed" || updated.Until != c.Until || updated.HTTP.State != "removed" || updated.HTTP.Reservation.SHA != ref.SHA {
				t.Fatal(updated, e)
			}
			if _, e = s.HTTPRecords(updated, deadline); !errors.Is(e, ErrExpired) {
				t.Fatal("terminal metadata revived disclosure", e)
			}
			root := s.root
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			if e = InspectVersion(root, key, 42); e != nil {
				t.Fatal("terminal reference inspection", e)
			}
			s, e = Open(root, key)
			if e != nil {
				t.Fatal("terminal reference restart", e)
			}
			defer s.Close()
			got, e := s.Get(c.ID)
			if e != nil || got.ETag() != updated.ETag() || got.HTTP.Reservation.SHA != ref.SHA {
				t.Fatal(got, e)
			}
		})
	}
}

func TestHTTPReconcileTerminalRejectsGapAndActiveCase(t *testing.T) {
	s, owner, c, actor, ref, entries, _, _ := reservedHTTPFixture(t)
	if _, e := s.ReconcileHTTPReservation(c.ID, actor, c.ETag(), ref, time.Now()); !errors.Is(e, ErrConflict) {
		t.Fatal("nonterminal case accepted", e)
	}
	b, e := s.HTTPReservationBinding(c, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = owner.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	b.Revision++
	if e = owner.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	latest, _, e := owner.OptionalHoldReceipt(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Release(c.ID, actor, c.ETag(), "terminal-gap-cancel", "cancel", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReconcileHTTPReservation(c.ID, actor, c.ETag(), latest, time.Now()); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("unproved two steps accepted", e)
	}
	got, e := s.Get(c.ID)
	if e != nil || got.ETag() != c.ETag() {
		t.Fatal("rejected gap changed case", got, e)
	}
}

func TestHTTPExportResumeAfterTerminalReservationMetadataUpdate(t *testing.T) {
	s, owner, c, actor, ref, entries, _, _ := reservedHTTPFixture(t)
	c, e := s.ResumeHTTPReserved(c.ID, actor, c.ETag(), entries, ref, time.Now(), reservationCheck(owner, ref))
	if e != nil {
		t.Fatal(e)
	}
	s.checkpoint = func(at string) error {
		if at == "export:intent" {
			return store.ErrIncomplete
		}
		return nil
	}
	c, _, e = s.Generate(c.ID, actor, c.ETag(), "terminal-export", "export", []string{"connection"}, time.Now())
	if !errors.Is(e, store.ErrIncomplete) || len(c.Exports) != 1 {
		t.Fatal(c, e)
	}
	export := c.Exports[0]
	if export.State != "preparing" {
		t.Fatal(export)
	}
	s.checkpoint = nil
	b := ref.Binding
	b.Revision = c.Revision
	if e = owner.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	latest, e := owner.CheckOptionalHoldReceipt(ref)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.ReconcileHTTPReservation(c.ID, actor, c.ETag(), latest, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	c, ready, e := s.ResumeExport(c.ID, export.ID, actor, c.ETag(), "terminal-export-resume", "resume", time.Now())
	if e != nil || ready.State != "ready" || ready.HTTPSelection != export.HTTPSelection || ready.Until != export.Until {
		t.Fatal("metadata update changed fixed export", c, ready, e)
	}
}
