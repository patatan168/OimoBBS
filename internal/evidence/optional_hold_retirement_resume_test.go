// 三つの保存停止点からの同一候補再開と、改変/欠落/認可拒否時の非変更を検査する。
package evidence

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func stoppedOptionalRetirementResumeFixture(t *testing.T, stop string) (*OptionalStore, ed25519.PrivateKey, OptionalHoldRetirementCandidate, domain.ID, time.Time) {
	t.Helper()
	s, _, b, entries, at := prepareOptionalRetirementFixture(t)
	live := b
	live.Case = domain.NewID()
	if err := s.ReserveOptionalHold(t.Context(), live, entries, at); err != nil {
		t.Fatal(err)
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
	key := slices.Clone(s.key)
	t.Cleanup(func() { clear(key) })
	injected := errors.New("stop retirement")
	s.checkpoint = func(point string) error {
		if point == stop {
			return injected
		}
		return nil
	}
	if stop != "not-started" {
		if err := s.CommitOptionalHoldRetirement(t.Context(), candidate, OptionalHoldRetirementReader, at, allowOptionalRetirement); !errors.Is(err, injected) {
			t.Fatal("stop was not reached", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return s, key, candidate, live.Case, at
}

func TestOptionalHoldRetirementResumePreservesLiveSourcesAndIsIdempotent(t *testing.T) {
	for _, stop := range []string{"not-started", "hold-index:sync", "hold-index:rename", "hold-retirement:unlink"} {
		t.Run(stop, func(t *testing.T) {
			s, key, candidate, live, at := stoppedOptionalRetirementResumeFixture(t, stop)
			before := snapshotOptionalRetirementFiles(t, s)
			inspect := &OptionalStore{root: s.root, site: s.site, key: key}
			if _, err := inspect.inspectOptionalRetirementResume(candidate, at); err != nil {
				t.Fatal("read-only stopped inspection", err)
			}
			if !reflect.DeepEqual(before, snapshotOptionalRetirementFiles(t, s)) {
				t.Fatal("inspection resumed retirement")
			}
			if err := ResumeOptionalHoldRetirement(t.Context(), s.root, s.site, key, candidate, OptionalHoldRetirementReader, at, allowOptionalRetirement); err != nil {
				t.Fatal("resume", err)
			}
			assertResumedOptionalRetirement(t, s, key, candidate, live, before[live.String()+".json"], at)
		})
	}
}

func assertResumedOptionalRetirement(t *testing.T, s *OptionalStore, key ed25519.PrivateKey, candidate OptionalHoldRetirementCandidate, live domain.ID, liveBytes string, at time.Time) {
	t.Helper()
	after := snapshotOptionalRetirementFiles(t, s)
	if len(after) != 2 || after[live.String()+".json"] != liveBytes {
		t.Fatal("resume lost or changed remaining source")
	}
	inspect := &OptionalStore{root: s.root, site: s.site, key: key}
	current, err := inspect.decodeOptionalHoldIndex([]byte(after[optionalHoldIndexFile]))
	if err != nil || !equalOptionalHoldBytes(current.event, candidate.Next) {
		t.Fatal("resume replaced authorized candidate", err)
	}
	if err := ResumeOptionalHoldRetirement(t.Context(), s.root, s.site, key, candidate, OptionalHoldRetirementReader, at, allowOptionalRetirement); err != nil {
		t.Fatal("resume replay", err)
	}
	if !reflect.DeepEqual(after, snapshotOptionalRetirementFiles(t, s)) {
		t.Fatal("resume replay changed files")
	}
}

func TestOptionalHoldRetirementResumeRejectsUntrustedStateWithoutChanges(t *testing.T) {
	for _, change := range []string{"unknown", "live-missing", "pending-tamper", "denied", "reader", "clock"} {
		t.Run(change, func(t *testing.T) {
			s, key, candidate, live, at := stoppedOptionalRetirementResumeFixture(t, "hold-index:sync")
			alterOptionalRetirementResumeFiles(t, s, live, change)
			check := allowOptionalRetirement
			reader := OptionalHoldRetirementReader
			switch change {
			case "denied":
				check = func(OptionalHoldRetirementCandidate) error { return store.ErrCorrupt }
			case "reader":
				reader--
			case "clock":
				at = at.Add(-time.Second)
			}
			before := snapshotOptionalRetirementFiles(t, s)
			if err := ResumeOptionalHoldRetirement(t.Context(), s.root, s.site, key, candidate, reader, at, check); err == nil {
				t.Fatal("invalid resume accepted")
			}
			if !reflect.DeepEqual(before, snapshotOptionalRetirementFiles(t, s)) {
				t.Fatal("rejected resume modified files")
			}
		})
	}
}

func alterOptionalRetirementResumeFiles(t *testing.T, s *OptionalStore, live domain.ID, change string) {
	t.Helper()
	dir := filepath.Join(s.root, optionalHoldsDir)
	var err error
	switch change {
	case "unknown":
		err = os.WriteFile(filepath.Join(dir, "unknown.json"), []byte("{}"), 0600)
	case "live-missing":
		err = os.Remove(s.holdFile(live))
	case "pending-tamper":
		err = os.WriteFile(filepath.Join(dir, optionalHoldIndexFile+".pending"), []byte("{}"), 0600)
	}
	if err != nil {
		t.Fatal(err)
	}
}
