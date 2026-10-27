// 稼働中の案件照合が原本回収より先行し、巻戻しと拒否でfileを保持することを検査する。
package evidence

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/store"
)

func TestOptionalSweepCheckedRejectsBeforeOriginalReclaim(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	defer s.Close()
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	before := optionalFileTree(t, s.root)
	rejected := errors.New("case/source deadline mismatch")
	reservations := 0
	reserve := func(int64) (func(), error) { reservations++; return func() {}, nil }
	check := func(v OptionalHoldReferences) error {
		if s.mu.TryLock() {
			s.mu.Unlock()
			t.Fatal("guard outside owner lock")
		}
		rows, e := v.OptionalHoldReceipts()
		if e != nil || len(rows) != 1 {
			t.Fatal(rows, e)
		}
		return rejected
	}
	cut := now.Add(31 * 24 * time.Hour)
	if n, e := s.SweepReservedChecked(cut, reserve, check); n != 0 || !errors.Is(e, rejected) {
		t.Fatal(n, e)
	}
	if reservations != 0 || !s.cleanupFailed {
		t.Fatal("rejected guard entered reclaim", reservations)
	}
	assertOptionalTreeEqual(t, before, optionalFileTree(t, s.root))
	if n, e := s.SweepReservedChecked(cut, reserve, func(OptionalHoldReferences) error { return nil }); e != nil || n < 1 {
		t.Fatal("allowed reclaim", n, e)
	}
	if reservations == 0 || s.cleanupFailed {
		t.Fatal("allowed guard failed to reclaim")
	}
}

func TestOptionalSweepCheckedRejectsKnownSignedRollbackBeforeCallback(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	defer s.Close()
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(s.root, OptionalHoldsDirectory, b.Case.String()+".json")
	old, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	b.Revision++
	if e = s.ReserveOptionalHold(context.Background(), b, entries, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	current, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	reference, found, e := s.OptionalHoldReceipt(b.Case)
	if e != nil || !found {
		t.Fatal(found, e)
	}
	if e = os.WriteFile(file, old, 0600); e != nil {
		t.Fatal(e)
	}
	before := optionalFileTree(t, s.root)
	called := false
	n, e := s.SweepReservedChecked(now.Add(31*24*time.Hour), func(int64) (func(), error) { t.Fatal("rollback entered reserve"); return nil, nil }, func(OptionalHoldReferences) error { called = true; return nil })
	if n != 0 || !errors.Is(e, store.ErrCorrupt) || called || !s.holdsStopped {
		t.Fatal(n, e, called, s.holdsStopped)
	}
	assertOptionalTreeEqual(t, before, optionalFileTree(t, s.root))
	if e = os.WriteFile(file, current, 0600); e != nil {
		t.Fatal(e)
	}
	n, e = s.SweepReservedChecked(now.Add(31*24*time.Hour), func(int64) (func(), error) { return func() {}, nil }, func(v OptionalHoldReferences) error { _, err := v.CheckOptionalHoldReceipt(reference); return err })
	if e != nil || n < 1 || s.holdsStopped || s.cleanupFailed {
		t.Fatal("repaired reference failed to resume", n, e)
	}
}

// assertOptionalTreeEqual は拒否時の原本と予約正本の非変更を全fileで検査する。
func assertOptionalTreeEqual(t *testing.T, before, after map[string][]byte) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatal("file set changed")
	}
	for name, raw := range before {
		if !bytes.Equal(raw, after[name]) {
			t.Fatal("file changed", name)
		}
	}
}
