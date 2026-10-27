// 回収対応索引の保存・物理解除回収・枠再利用と、認可拒否/保存停止中のGC拒否を検査する。
package evidence

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func prepareOptionalRetirementFixture(t *testing.T) (*OptionalStore, OptionalHoldRetirementCandidate, OptionalHoldBinding, []Entry, time.Time) {
	t.Helper()
	s, _, b, entries, now := optionalHoldFixture(t)
	if err := s.ReserveOptionalHold(t.Context(), b, entries, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseOptionalHold(t.Context(), b.Case, 2, now); err != nil {
		t.Fatal(err)
	}
	released, _, err := s.OptionalHoldReceipt(b.Case)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(0, int64(max(s.floor, s.holdIndex.payload.At))+1)
	candidate, err := s.PrepareOptionalHoldRetirement(t.Context(), released, domain.Hash{1}, domain.Hash{2}, at)
	if err != nil {
		t.Fatal(err)
	}
	return s, candidate, b, entries, at
}

func TestCommitOptionalHoldRetirementFreesSourceSlotAtCapacity(t *testing.T) {
	s, first, b, entries, at := prepareOptionalRetirementFixture(t)
	// 候補構成後の索引進行は古い候補を無効にする。
	var survivor domain.ID
	for range MaxOptionalHolds - 1 {
		next := b
		next.Case = domain.NewID()
		if err := s.ReserveOptionalHold(t.Context(), next, entries, at); err != nil {
			t.Fatal(err)
		}
		survivor = next.Case
	}
	if err := s.CommitOptionalHoldRetirement(t.Context(), first, OptionalHoldRetirementReader, at, allowOptionalRetirement); !errors.Is(err, store.ErrCorrupt) {
		t.Fatal("stale index candidate accepted", err)
	}
	released, _, err := s.OptionalHoldReceipt(b.Case)
	if err != nil {
		t.Fatal(err)
	}
	at = time.Unix(0, int64(max(s.floor, s.holdIndex.payload.At))+1)
	candidate, err := s.PrepareOptionalHoldRetirement(t.Context(), released, domain.Hash{1}, domain.Hash{2}, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CommitOptionalHoldRetirement(t.Context(), candidate, OptionalHoldRetirementReader, at, allowOptionalRetirement); err != nil {
		t.Fatal(err)
	}
	if !equalOptionalHoldBytes(s.holdIndex.event, candidate.Next) {
		t.Fatal("saved index differs from authorized signed candidate")
	}
	if _, err := os.Lstat(s.holdFile(b.Case)); !os.IsNotExist(err) {
		t.Fatal("released source file remains", err)
	}
	assertOptionalRetirementReplacement(t, s, b, survivor, entries, at)
}

func allowOptionalRetirement(OptionalHoldRetirementCandidate) error { return nil }

func assertOptionalRetirementReplacement(t *testing.T, s *OptionalStore, b OptionalHoldBinding, survivor domain.ID, entries []Entry, at time.Time) {
	t.Helper()
	rows, err := s.OptionalHoldReceipts()
	if err != nil || len(rows) != MaxOptionalHolds-1 {
		t.Fatal("retired source still occupies capacity", len(rows), err)
	}
	next := b
	next.Case = domain.NewID()
	if err := s.ReserveOptionalHold(t.Context(), next, entries, at); err != nil {
		t.Fatal("replacement reservation rejected", err)
	}
	rows, err = s.OptionalHoldReceipts()
	if err != nil || len(rows) != MaxOptionalHolds {
		t.Fatal("replacement capacity", len(rows), err)
	}
	assertOptionalRetirementSurvivor(t, s, survivor, entries, at)
}

func assertOptionalRetirementSurvivor(t *testing.T, s *OptionalStore, survivor domain.ID, entries []Entry, at time.Time) {
	t.Helper()
	if n, err := s.Sweep(at.Add(2 * time.Minute)); err != nil || n != 0 {
		t.Fatal("remaining holds lost protection", n, err)
	}
	held, err := s.QueryOptionalHold(t.Context(), survivor, at.Add(2*time.Minute))
	if err != nil || len(held) != len(entries) || held[0].Event.EventSHA != entries[0].Event.EventSHA {
		t.Fatal("survivor source changed", err)
	}
}

func TestCommitOptionalHoldRetirementDeniedPreservesAllFiles(t *testing.T) {
	for _, mode := range []string{"nil", "denied", "reader", "canceled", "clock"} {
		t.Run(mode, func(t *testing.T) {
			s, candidate, _, _, at := prepareOptionalRetirementFixture(t)
			before := snapshotOptionalRetirementFiles(t, s)
			ctx, reader, check := t.Context(), OptionalHoldRetirementReader, allowOptionalRetirement
			switch mode {
			case "nil":
				check = nil
			case "denied":
				check = func(OptionalHoldRetirementCandidate) error { return store.ErrCorrupt }
			case "reader":
				reader--
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "clock":
				at = at.Add(-time.Second)
			}
			if err := s.CommitOptionalHoldRetirement(ctx, candidate, reader, at, check); err == nil {
				t.Fatal("invalid retirement accepted")
			}
			if !reflect.DeepEqual(before, snapshotOptionalRetirementFiles(t, s)) {
				t.Fatal("denied retirement changed files")
			}
		})
	}
}

func TestCommitOptionalHoldRetirementStopRefusesGCAndAutomaticResume(t *testing.T) {
	for _, stop := range []string{"hold-index:sync", "hold-index:rename", "hold-retirement:unlink"} {
		t.Run(stop, func(t *testing.T) {
			s, candidate, _, _, at := prepareOptionalRetirementFixture(t)
			injected := errors.New("retirement storage stop")
			s.checkpoint = func(point string) error {
				if point == stop {
					return injected
				}
				return nil
			}
			if err := s.CommitOptionalHoldRetirement(t.Context(), candidate, OptionalHoldRetirementReader, at, allowOptionalRetirement); !errors.Is(err, injected) {
				t.Fatal("missing injected stop", err)
			}
			assertStoppedOptionalRetirement(t, s, at)
		})
	}
}

func assertStoppedOptionalRetirement(t *testing.T, s *OptionalStore, at time.Time) {
	t.Helper()
	before := snapshotOptionalRetirementFiles(t, s)
	if _, err := s.Sweep(at.Add(2 * time.Minute)); !errors.Is(err, store.ErrIncomplete) {
		t.Fatal("uncertain retirement allowed GC", err)
	}
	if err := s.ReloadOptionalHolds(); !errors.Is(err, store.ErrIncomplete) {
		t.Fatal("ordinary reload resumed without authorization", err)
	}
	if _, err := s.SweepReservedChecked(at, func(int64) (func(), error) { t.Fatal("uncertain retirement reserved GC"); return nil, nil }, func(OptionalHoldReferences) error { t.Fatal("uncertain retirement entered normal check"); return nil }); !errors.Is(err, store.ErrIncomplete) {
		t.Fatal("ordinary checked GC resumed retirement", err)
	}
	key := slices.Clone(s.key)
	defer clear(key)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenOptionalStore(s.root, s.site, key); !errors.Is(err, store.ErrIncomplete) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatal("ordinary startup adopted retirement without authorization")
	}
	if !reflect.DeepEqual(before, snapshotOptionalRetirementFiles(t, s)) {
		t.Fatal("stopped retirement changed without authorization")
	}
}
