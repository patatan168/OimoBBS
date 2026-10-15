// 案件参照から元所有者の最新署名状態への一致/直後進行・巻戻し拒否・独立所有を実fileで検査する。
package evidence

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestOptionalHoldReceiptProofExactNextReleaseAndRestart(t *testing.T) {
	s, key, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	first, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := s.CheckOptionalHoldReceipt(first); e != nil || got.SHA != first.SHA {
		t.Fatal(got, e)
	}
	b.Revision++
	b.Until += domain.Time(time.Hour)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	second, e := s.CheckOptionalHoldReceipt(first)
	if e != nil || second.Sequence != first.Sequence+1 || second.Binding.Until != b.Until {
		t.Fatal("unreflected next reservation", second, e)
	}
	if e := s.ReleaseOptionalHold(context.Background(), b.Case, b.Revision+1, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.CheckOptionalHoldReceipt(first); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("unproved two-step chain accepted", e)
	}
	released, e := s.CheckOptionalHoldReceipt(second)
	if e != nil || released.State != "released" {
		t.Fatal("next release rejected", released, e)
	}
	root, site := s.root, s.site
	s.Close()
	s, e = OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if got, e := s.CheckOptionalHoldReceipt(second); e != nil || got.SHA != released.SHA {
		t.Fatal("release proof after restart", got, e)
	}
	if _, e := s.QueryOptionalHold(context.Background(), b.Case, time.Now()); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("release proof authorized body query", e)
	}
}

func TestOptionalHoldReceiptProofRejectsWrongReferenceAndRollback(t *testing.T) {
	for _, change := range []string{"site", "hash", "future-seq", "revision", "items"} {
		t.Run(change, func(t *testing.T) {
			s, _, b, entries, now := optionalHoldFixture(t)
			if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
				t.Fatal(e)
			}
			ref, _, e := s.OptionalHoldReceipt(b.Case)
			if e != nil {
				t.Fatal(e)
			}
			switch change {
			case "site":
				ref.Site = domain.NewID()
			case "hash":
				ref.SHA[0] ^= 1
			case "future-seq":
				ref.Sequence++
			case "revision":
				ref.Binding.Revision++
			case "items":
				ref.Items = slices.Clone(ref.Items)
				ref.Items[0].Expires++
			}
			if _, e := s.CheckOptionalHoldReceipt(ref); !errors.Is(e, store.ErrCorrupt) {
				t.Fatal("changed reference accepted", e)
			}
		})
	}
	s, _, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	old := s.holds[b.Case]
	b.Revision++
	if e := s.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	current, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil {
		t.Fatal(e)
	}
	s.holds[b.Case] = old
	if _, e := s.CheckOptionalHoldReceipt(current); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("old legitimate source snapshot accepted", e)
	}
}

func TestOptionalHoldReceiptProofChecksNextHashAndOwnedSet(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	first, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil {
		t.Fatal(e)
	}
	b.Revision++
	if e := s.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	saved := s.holds[b.Case]
	saved.event.PreviousSHA = domain.Hash{}
	s.holds[b.Case] = saved
	if _, e := s.CheckOptionalHoldReceipt(first); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("seq alone proved advance", e)
	}
	rows, e := s.OptionalHoldReceipts()
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	rows[0].Items[0].Record = domain.NewID()
	rows[0].Binding.Operations[0] = domain.NewID()
	again, e := s.OptionalHoldReceipts()
	if e != nil || again[0].Items[0].Record != first.Items[0].Record || again[0].Binding.Operations[0] != first.Binding.Operations[0] {
		t.Fatal("receipt set aliases source ledger", again, e)
	}
	s.holdsStopped = true
	if _, e := s.OptionalHoldReceipts(); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("uncertain owner published set", e)
	}
}
