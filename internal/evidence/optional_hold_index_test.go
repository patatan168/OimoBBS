// 元予約の署名集合索引による新起動の欠落検出と、同期途中の非変更検査・補完を実fileで検査する。
package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestOptionalHoldIndexNewOwnerRejectsMissingFiles(t *testing.T) {
	for _, missing := range []string{"case", "index"} {
		t.Run(missing, func(t *testing.T) {
			s, key, b, entries, now := optionalHoldFixture(t)
			if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
				t.Fatal(e)
			}
			root, site := s.root, s.site
			path := s.holdFile(b.Case)
			if missing == "index" {
				path = filepath.Join(root, optionalHoldsDir, optionalHoldIndexFile)
			}
			s.Close()
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
			before, e := os.ReadDir(filepath.Join(root, optionalHoldsDir))
			if e != nil {
				t.Fatal(e)
			}
			if e = InspectOptionalStore(root, site, key); !errors.Is(e, store.ErrCorrupt) {
				t.Fatal("read-only accepted missing reservation ledger", e)
			}
			if owner, e := OpenOptionalStore(root, site, key); e == nil {
				owner.Close()
				t.Fatal("new owner accepted missing reservation ledger")
			}
			after, e := os.ReadDir(filepath.Join(root, optionalHoldsDir))
			if e != nil || len(before) != len(after) {
				t.Fatal("missing proof was silently repaired", e)
			}
		})
	}
}

func TestOptionalHoldIndexRegistrationStopPreservesSource(t *testing.T) {
	for _, stop := range []string{"hold-index:sync", "hold-index:rename"} {
		t.Run(stop, func(t *testing.T) {
			s, key, b, entries, now := optionalHoldFixture(t)
			if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
				t.Fatal(e)
			}
			second := b
			second.Case = domain.NewID()
			injected := errors.New("stop index registration")
			s.checkpoint = func(at string) error {
				if at == stop {
					return injected
				}
				return nil
			}
			if e := s.ReserveOptionalHold(context.Background(), second, entries, now); !errors.Is(e, injected) {
				t.Fatal(e)
			}
			if _, e := s.Sweep(now.Add(2 * time.Minute)); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("uncertain index allowed GC", e)
			}
			root, site := s.root, s.site
			pending := s.holdFile(second.Case) + ".pending"
			original, e := os.ReadFile(pending)
			if e != nil {
				t.Fatal(e)
			}
			s.Close()
			if e := InspectOptionalStore(root, site, key); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("read-only recovered pending reservation", e)
			}
			unchanged, e := os.ReadFile(pending)
			if e != nil || string(unchanged) != string(original) {
				t.Fatal("read-only changed reservation candidate", e)
			}
			s, e = OpenOptionalStore(root, site, key)
			if e != nil {
				t.Fatal("new owner recovery", e)
			}
			defer s.Close()
			if len(s.holdIndex.payload.Cases) != 2 {
				t.Fatal("registration omitted after recovery")
			}
			if e := s.ReleaseOptionalHold(context.Background(), b.Case, 2, now); e != nil {
				t.Fatal(e)
			}
			if n, e := s.Sweep(now.Add(2 * time.Minute)); e != nil || n != 0 {
				t.Fatal("new reservation did not protect original", n, e)
			}
			if rows, e := s.QueryOptionalHold(context.Background(), second.Case, now.Add(2*time.Minute)); e != nil || len(rows) != 1 {
				t.Fatal("new reservation missing", len(rows), e)
			}
		})
	}
}

func TestOptionalHoldIndexRejectsSignedSetRemovalAndTamper(t *testing.T) {
	for _, corruption := range []string{"signed-removal", "signature", "site"} {
		t.Run(corruption, func(t *testing.T) {
			s, key, b, entries, now := optionalHoldFixture(t)
			if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
				t.Fatal(e)
			}
			p, previous := s.holdIndex.payload, s.holdIndex.event.EventSHA
			p.Sequence++
			p.At = max(p.At, domain.Time(time.Now().UnixNano()))
			if corruption == "signed-removal" {
				p.Cases = []domain.ID{}
			}
			if corruption == "site" {
				p.Site = domain.NewID()
			}
			body, e := json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			event, e := Seal(Source{optionalHoldIndexOwner(s.site), 0, uint64(p.Sequence)}, s.site, "checkpoint", body, previous, 10, key)
			if e != nil {
				t.Fatal(e)
			}
			if corruption == "signature" {
				event.Signature = "AAAA"
			}
			raw, e := json.Marshal(event)
			if e != nil {
				t.Fatal(e)
			}
			candidate := filepath.Join(s.root, optionalHoldsDir, optionalHoldIndexFile+".pending")
			if e := os.WriteFile(candidate, raw, 0600); e != nil {
				t.Fatal(e)
			}
			if e := s.ReloadOptionalHolds(); !errors.Is(e, store.ErrCorrupt) {
				t.Fatal("accepted altered index", e)
			}
			if retained, e := os.ReadFile(candidate); e != nil || string(retained) != string(raw) {
				t.Fatal("altered candidate not retained", e)
			}
			if _, e := s.Sweep(now.Add(2 * time.Minute)); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("invalid index allowed GC", e)
			}
		})
	}
}

func TestOptionalHoldIndexInitializationAndRequiredPresence(t *testing.T) {
	for _, missing := range []string{"index", "directory"} {
		t.Run(missing, func(t *testing.T) {
			s, key, _, entries, _ := optionalHoldFixture(t)
			if e := InspectOptionalHoldSet(s.root, bindingSite(entries[0]), key); !errors.Is(e, store.ErrCorrupt) {
				t.Fatal("uninitialized set accepted", e)
			}
			if e := s.InitializeOptionalHolds(); e != nil {
				t.Fatal(e)
			}
			first := s.holdIndex.event.EventSHA
			if e := s.InitializeOptionalHolds(); e != nil || s.holdIndex.event.EventSHA != first {
				t.Fatal("initialization not idempotent", e)
			}
			if e := InspectOptionalHoldSet(s.root, s.site, key); e != nil {
				t.Fatal("signed empty set rejected", e)
			}
			root, site := s.root, s.site
			s.Close()
			path := filepath.Join(root, optionalHoldsDir, optionalHoldIndexFile)
			if missing == "directory" {
				path = filepath.Join(root, optionalHoldsDir)
			}
			if e := os.RemoveAll(path); e != nil {
				t.Fatal(e)
			}
			if e := InspectOptionalHoldSet(root, site, key); !errors.Is(e, store.ErrCorrupt) {
				t.Fatal("active expected set missing accepted", e)
			}
			if _, e := os.Stat(path); !os.IsNotExist(e) {
				t.Fatal("read-only re-created missing ledger", e)
			}
		})
	}
}

func TestOptionalHoldIndexInitializationInterrupted(t *testing.T) {
	for _, stop := range []string{"hold-index:sync", "hold-index:rename"} {
		t.Run(stop, func(t *testing.T) {
			s, key, _, _, _ := optionalHoldFixture(t)
			injected := errors.New("stop empty index initialization")
			s.checkpoint = func(at string) error {
				if at == stop {
					return injected
				}
				return nil
			}
			if e := s.InitializeOptionalHolds(); !errors.Is(e, injected) {
				t.Fatal(e)
			}
			root, site := s.root, s.site
			s.Close()
			if stop == "hold-index:sync" {
				if e := InspectOptionalHoldSet(root, site, key); !errors.Is(e, store.ErrIncomplete) {
					t.Fatal("read-only recovered initialization", e)
				}
			}
			reopened, e := OpenOptionalStore(root, site, key)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if len(reopened.holdIndex.payload.Cases) != 0 || reopened.holdIndex.payload.Sequence != 1 {
				t.Fatal("initialization changed expected set")
			}
			if e := InspectOptionalHoldSet(root, site, key); e != nil {
				t.Fatal("recovered initialization rejected", e)
			}
		})
	}
}

func TestOptionalHoldIndexRegisteredCandidateMissingBlocksRecovery(t *testing.T) {
	s, key, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	b.Case = domain.NewID()
	injected := errors.New("stop after new registration")
	s.checkpoint = func(at string) error {
		if at == "hold-index:rename" {
			return injected
		}
		return nil
	}
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); !errors.Is(e, injected) {
		t.Fatal(e)
	}
	root, site := s.root, s.site
	pending := s.holdFile(b.Case) + ".pending"
	s.Close()
	if e := os.Remove(pending); e != nil {
		t.Fatal(e)
	}
	if e := InspectOptionalHoldSet(root, site, key); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("registered candidate missing accepted", e)
	}
	if reopened, e := OpenOptionalStore(root, site, key); e == nil {
		reopened.Close()
		t.Fatal("missing candidate was recreated")
	}
}

func TestOptionalHoldIndexOldSetCannotHideExistingNewCase(t *testing.T) {
	s, key, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(s.root, optionalHoldsDir, optionalHoldIndexFile)
	old, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	b.Case = domain.NewID()
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	root, site := s.root, s.site
	s.Close()
	if e := os.WriteFile(path, old, 0600); e != nil {
		t.Fatal(e)
	}
	if e := InspectOptionalHoldSet(root, site, key); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("old signed set concealed unregistered canonical case", e)
	}
	if reopened, e := OpenOptionalStore(root, site, key); e == nil {
		reopened.Close()
		t.Fatal("old signed set was silently expanded")
	}
}
