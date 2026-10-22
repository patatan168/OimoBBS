// 帯域変更が送信中の予約を維持し、取消・終了時の規則も保つことを検証する。
package delivery

import (
	"errors"
	"net/netip"
	"testing"
)

func TestBudgetUpdatePreservesPermit(t *testing.T) {
	s, e := New(DefaultBudgetBits)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p, e := s.Reserve(t.Context(), netip.MustParseAddr("192.0.2.1"), Chunk)
	if e != nil {
		t.Fatal(e)
	}
	before := s.Status()
	if e = s.UpdateBudget(40_000_000); e != nil {
		t.Fatal(e)
	}
	after := s.Status()
	if after.Budget != 40_000_000 || after.Active != before.Active || after.Reserved != before.Reserved {
		t.Fatal("reservation lost", after)
	}
	p.Release()
	if s.Status().Active != 0 {
		t.Fatal("release")
	}
	if s.UpdateBudget(0) == nil || s.Status().Budget != 40_000_000 {
		t.Fatal("invalid update")
	}
	s.Close()
	if !errors.Is(s.UpdateBudget(DefaultBudgetBits), ErrClosed) {
		t.Fatal("closed update")
	}
}
