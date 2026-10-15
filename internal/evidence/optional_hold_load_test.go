// 最大保全集合と大量の満了原本を競合させ、同期境界・重複予約・物理回収を検査する。
package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

type optionalHeldLoad struct {
	store   *OptionalStore
	key     ed25519.PrivateKey
	site    domain.ID
	binding OptionalHoldBinding
	entries []Entry
	now     time.Time
}

func newOptionalHeldLoad(t *testing.T) optionalHeldLoad {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	site, board := domain.NewID(), domain.NewID()
	s, err := OpenOptionalStore(root, site, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Now()
	received := domain.Time(now.Add(-OptionalRetention + time.Hour).UnixNano())
	ids := appendOptionalHeldLoad(t, s, site, board, received)
	scope := OptionalQueryScope{Board: board, From: received, To: received + 1, Records: ids}
	entries, err := s.QueryUnboundSigned(t.Context(), scope, now)
	if err != nil || len(entries) != MaxOptionalQueryRecords {
		t.Fatal("maximum selection", len(entries), err)
	}
	binding := OptionalHoldBinding{Unbound: true, Case: domain.NewID(), Revision: 2, Board: board, From: scope.From, To: scope.To, Operations: []domain.ID{}, Until: domain.Time(now.Add(30 * 24 * time.Hour).UnixNano())}
	return optionalHeldLoad{s, key, site, binding, entries, now}
}

func appendOptionalHeldLoad(t *testing.T, s *OptionalStore, site, board domain.ID, received domain.Time) []domain.ID {
	t.Helper()
	ids := []domain.ID{}
	for i := range 1025 {
		r := optionalFixture()
		r.Site, r.Board = site, &board
		r.Received, r.Finished, r.Until = received, received+100, received+domain.Time(OptionalRetention)
		if err := s.Write(t.Context(), r); err != nil {
			t.Fatal(i, err)
		}
		if i < MaxOptionalQueryRecords {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

func TestOptionalMaximumHoldDuringLoadedSweepAndRestart(t *testing.T) {
	f := newOptionalHeldLoad(t)
	second := f.binding
	second.Case = domain.NewID()
	if err := f.store.ReserveOptionalHold(t.Context(), second, f.entries[:50], f.now); err != nil {
		t.Fatal(err)
	}
	cut := f.now.Add(2 * time.Hour)
	reserveMaximumDuringSweep(t, f, cut)
	assertOptionalHeldLoadEntries(t, f.store, f.binding.Case, f.entries, cut)
	assertOptionalHeldLoadOrdinaryExpired(t, f, cut)
	root := f.store.root
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := InspectOptionalStore(root, f.site, f.key); err != nil {
		t.Fatal("read-only recovery verification", err)
	}
	s, err := OpenOptionalStore(root, f.site, f.key)
	if err != nil {
		t.Fatal("restart", err)
	}
	defer s.Close()
	assertOptionalHeldLoadEntries(t, s, f.binding.Case, f.entries, cut)
	assertOptionalOverlappingLoadRelease(t, s, f, second, cut)
}

// reserveMaximumDuringSweep は元予約のSync内でGCを開始し、同じ所有者の排他を競合させる。
func reserveMaximumDuringSweep(t *testing.T, f optionalHeldLoad, cut time.Time) {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	f.store.checkpoint = func(stage string) error {
		if stage == "hold:sync" {
			close(entered)
			<-release
		}
		return nil
	}
	reserved := make(chan error, 1)
	go func() { reserved <- f.store.ReserveOptionalHold(context.Background(), f.binding, f.entries, f.now) }()
	select {
	case <-entered:
	case err := <-reserved:
		t.Fatal("reservation ended before Sync barrier", err)
	}
	started := make(chan struct{})
	swept := make(chan error, 1)
	go func() {
		close(started)
		n, err := f.store.Sweep(cut)
		if err == nil && n != 1025-MaxOptionalQueryRecords {
			err = ErrOptionalQueryScope
		}
		swept <- err
	}()
	<-started
	close(release)
	if err := <-reserved; err != nil {
		t.Fatal("reserve", err)
	}
	if err := <-swept; err != nil {
		t.Fatal("loaded sweep", err)
	}
	f.store.checkpoint = nil
	for _, entry := range f.entries {
		day := optionalEntryDay(t, entry)
		if _, err := os.Stat(filepath.Join(f.store.root, day, "control-000001.wal")); !os.IsNotExist(err) {
			t.Fatal("expired original WAL retained", err)
		}
		break
	}
}

func optionalEntryDay(t *testing.T, entry Entry) string {
	t.Helper()
	verified, err := VerifyOptionalEntry(entry, bindingSite(entry), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return strconv.FormatUint(uint64(verified.SourceDay), 10)
}

func assertOptionalHeldLoadEntries(t *testing.T, s *OptionalStore, id domain.ID, originals []Entry, now time.Time) {
	t.Helper()
	held, err := s.QueryOptionalHold(t.Context(), id, now)
	if err != nil || len(held) != len(originals) {
		t.Fatal("held source count", len(held), err)
	}
	for i, entry := range held {
		if entry.Event != originals[i].Event || !bytes.Equal(entry.Payload, originals[i].Payload) {
			t.Fatal("held source changed", i)
		}
	}
}

func assertOptionalHeldLoadOrdinaryExpired(t *testing.T, f optionalHeldLoad, now time.Time) {
	t.Helper()
	rows, err := f.store.QueryUnbound(t.Context(), OptionalQueryScope{Board: f.binding.Board, From: f.binding.From, To: f.binding.To}, now)
	if err != nil || len(rows) != 0 {
		t.Fatal("expired held originals returned by ordinary query", len(rows), err)
	}
}

// assertOptionalOverlappingLoadRelease は先の100件を解除しても他案件の50件を保護することを確認する。
func assertOptionalOverlappingLoadRelease(t *testing.T, s *OptionalStore, f optionalHeldLoad, second OptionalHoldBinding, now time.Time) {
	t.Helper()
	if err := s.ReleaseOptionalHold(t.Context(), f.binding.Case, f.binding.Revision, now); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Sweep(now); err != nil || n != 50 {
		t.Fatal("overlapping reservation lost", n, err)
	}
	assertOptionalHeldLoadEntries(t, s, second.Case, f.entries[:50], now)
	if err := s.ReleaseOptionalHold(t.Context(), second.Case, second.Revision, now); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Sweep(now); err != nil || n != 50 {
		t.Fatal("final release retained sources", n, err)
	}
	if _, err := s.QueryOptionalHold(t.Context(), second.Case, now); err == nil {
		t.Fatal("released source remained readable")
	}
	assertOptionalLoadedDayRemoved(t, s, f.entries[0])
}

// assertOptionalLoadedDayRemoved は最終解除後の保全元が日別directoryごと物理回収されたことを確認する。
func assertOptionalLoadedDayRemoved(t *testing.T, s *OptionalStore, original Entry) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(s.root, optionalEntryDay(t, original))); !os.IsNotExist(err) {
		t.Fatal("released original files retained", err)
	}
}
