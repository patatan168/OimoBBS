// 元解除のCASが未保存の更新を飛ばさず、直後解除だけを冪等に扱うことを検査する。
package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"oimobbs/internal/store"
)

func TestOptionalHoldCheckedReleaseRejectsInterveningActiveUpdate(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	first, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil {
		t.Fatal(e)
	}
	b.Revision++
	if e = s.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	second, e := s.CheckOptionalHoldReceipt(first)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ReleaseOptionalHoldChecked(context.Background(), first, b.Revision+1, time.Now()); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("skipped unsaved active update", e)
	}
	current, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil || current.State != "active" || current.SHA != second.SHA {
		t.Fatal(current, e)
	}
	if e = s.ReleaseOptionalHoldChecked(context.Background(), second, b.Revision+1, time.Now()); e != nil {
		t.Fatal(e)
	}
	released, e := s.CheckOptionalHoldReceipt(second)
	if e != nil || released.State != "released" {
		t.Fatal(released, e)
	}
	if e = s.ReleaseOptionalHoldChecked(context.Background(), second, b.Revision+1, time.Now()); e != nil {
		t.Fatal("release replay", e)
	}
	latest, _, e := s.OptionalHoldReceipt(b.Case)
	if e != nil || latest.SHA != released.SHA {
		t.Fatal("release replay advanced seq", latest, e)
	}
}
