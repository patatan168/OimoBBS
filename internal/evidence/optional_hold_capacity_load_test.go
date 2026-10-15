// 128予約・各100原本での満杯拒否、再起動、最後の予約までの回収保護を検査する。
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

func TestOptionalFullHoldCapacityLoadedSweepAndRestart(t *testing.T) {
	f := newOptionalHeldLoad(t)
	bindings := reserveOptionalFullLoad(t, f)
	assertOptionalCapacityRejectionUnchanged(t, f)
	cut := f.now.Add(2 * time.Hour)
	if n, err := f.store.Sweep(cut); err != nil || n != 1025-MaxOptionalQueryRecords {
		t.Fatal("full capacity sweep", n, err)
	}
	assertOptionalHeldLoadEntries(t, f.store, bindings[MaxOptionalHolds-1].Case, f.entries, cut)
	root := f.store.root
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := InspectOptionalStore(root, f.site, f.key); err != nil {
		t.Fatal("full capacity inspection", err)
	}
	s, err := OpenOptionalStore(root, f.site, f.key)
	if err != nil {
		t.Fatal("full capacity restart", err)
	}
	defer s.Close()
	assertOptionalFullLoadRestart(t, s, bindings, f.entries, cut)
	releaseOptionalFullLoad(t, s, bindings, f.entries, cut)
}

func reserveOptionalFullLoad(t *testing.T, f optionalHeldLoad) []OptionalHoldBinding {
	t.Helper()
	bindings := make([]OptionalHoldBinding, MaxOptionalHolds)
	for i := range bindings {
		b := f.binding
		b.Case = domain.NewID()
		if err := f.store.ReserveOptionalHold(t.Context(), b, f.entries, f.now); err != nil {
			t.Fatal("reserve maximum capacity", i, err)
		}
		bindings[i] = b
	}
	return bindings
}

// assertOptionalCapacityRejectionUnchanged は129件目を拒否しても署名索引・参照・候補を変えないことを確認する。
func assertOptionalCapacityRejectionUnchanged(t *testing.T, f optionalHeldLoad) {
	t.Helper()
	before := optionalFullLoadReceipts(t, f.store)
	path := filepath.Join(f.store.root, optionalHoldsDir, optionalHoldIndexFile)
	index, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b := f.binding
	b.Case = domain.NewID()
	if err := f.store.ReserveOptionalHold(t.Context(), b, f.entries, f.now); !errors.Is(err, ErrOptionalQueryLimit) {
		t.Fatal("capacity exceeded", err)
	}
	after := optionalFullLoadReceipts(t, f.store)
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(index, current) || !bytes.Equal(before, after) {
		t.Fatal("capacity rejection changed durable reservations", err)
	}
	assertOptionalOverflowFilesAbsent(t, f.store, b.Case)
}

func optionalFullLoadReceipts(t *testing.T, s *OptionalStore) []byte {
	t.Helper()
	rows, err := s.OptionalHoldReceipts()
	if err != nil || len(rows) != MaxOptionalHolds {
		t.Fatal("full capacity receipts", len(rows), err)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertOptionalOverflowFilesAbsent(t *testing.T, s *OptionalStore, id domain.ID) {
	t.Helper()
	for _, path := range []string{s.holdFile(id), s.holdFile(id) + ".pending"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("overflow reservation created a file", err)
		}
	}
}

func assertOptionalFullLoadRestart(t *testing.T, s *OptionalStore, bindings []OptionalHoldBinding, entries []Entry, now time.Time) {
	t.Helper()
	rows, err := s.OptionalHoldReceipts()
	if err != nil || len(rows) != MaxOptionalHolds {
		t.Fatal("reservations missing after restart", len(rows), err)
	}
	for _, row := range rows {
		if row.State != "active" || len(row.Items) != MaxOptionalQueryRecords {
			t.Fatal("full selection missing after restart")
		}
	}
	assertOptionalHeldLoadEntries(t, s, bindings[0].Case, entries, now)
	assertOptionalHeldLoadEntries(t, s, bindings[MaxOptionalHolds-1].Case, entries, now)
}

// releaseOptionalFullLoad は127予約の解除後も最後の100件を保護し、最後の解除だけで回収する。
func releaseOptionalFullLoad(t *testing.T, s *OptionalStore, bindings []OptionalHoldBinding, entries []Entry, now time.Time) {
	t.Helper()
	for _, b := range bindings[:MaxOptionalHolds-1] {
		if err := s.ReleaseOptionalHold(t.Context(), b.Case, b.Revision, now); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.Sweep(now); err != nil || n != 0 {
		t.Fatal("last active reservation lost", n, err)
	}
	last := bindings[MaxOptionalHolds-1]
	assertOptionalHeldLoadEntries(t, s, last.Case, entries, now)
	if err := s.ReleaseOptionalHold(t.Context(), last.Case, last.Revision, now); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Sweep(now); err != nil || n != MaxOptionalQueryRecords {
		t.Fatal("last release retained original", n, err)
	}
	assertOptionalLoadedDayRemoved(t, s, entries[0])
}
