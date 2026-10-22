// 原本保全予約の同期・部分GC除外・複数案件・停止点復旧と期限/解除回収を実fileで検査する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func optionalHoldFixture(t *testing.T) (*OptionalStore, ed25519.PrivateKey, OptionalHoldBinding, []Entry, time.Time) {
	t.Helper()
	s, key, r, scope := signedOptionalFixture(t)
	now := time.Now()
	// 同日のもう一つの原本を作り、期限回収時に保全/非保全を分ける。
	r.ID = domain.NewID()
	r.Received = domain.Time(now.Add(-OptionalRetention + time.Minute).UnixNano())
	r.Finished, r.Until = r.Received+100, r.Received+domain.Time(OptionalRetention)
	if e := s.Write(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	scope.From, scope.To = r.Received, r.Received+1000
	entries, e := s.QuerySigned(context.Background(), scope, now)
	if e != nil || len(entries) != 1 {
		t.Fatal(len(entries), e)
	}
	b := OptionalHoldBinding{Case: domain.NewID(), Revision: 1, Board: scope.Board, From: scope.From, To: scope.To, Operations: slices.Clone(scope.Operations), Until: domain.Time(now.Add(30 * 24 * time.Hour).UnixNano())}
	return s, key, b, entries, now
}

func TestOptionalHoldProtectsOriginalThroughGCAndRestart(t *testing.T) {
	s, key, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	// 呼出元のslice変更で署名済み予約の範囲を変えない。
	b.Operations[0] = domain.NewID()
	if s.holds[b.Case].payload.Binding.Operations[0] == b.Operations[0] {
		t.Fatal("scope alias retained")
	}
	b = s.holds[b.Case].payload.Binding
	cut := now.Add(2 * time.Minute)
	if n, e := s.Sweep(cut); e != nil || n != 0 {
		t.Fatal("held original removed", n, e)
	}
	rows, e := s.QueryOptionalHold(context.Background(), b.Case, cut)
	if e != nil || len(rows) != 1 || rows[0].Event.EventSHA != entries[0].Event.EventSHA {
		t.Fatal(rows, e)
	}
	ordinary, e := optionalRecordsForTest(s, false, context.Background(), OptionalQueryScope{Board: b.Board, From: b.From, To: b.To, Operations: b.Operations}, cut)
	if e != nil || len(ordinary) != 0 {
		t.Fatal("reservation exposed ordinary expired source", ordinary, e)
	}
	root := s.root
	s.Close()
	if e := InspectOptionalStore(root, bindingSite(entries[0]), key); e != nil {
		t.Fatal("read-only pin verification", e)
	}
	s, e = OpenOptionalStore(root, bindingSite(entries[0]), key)
	if e != nil {
		t.Fatal("restart", e)
	}
	defer s.Close()
	if _, e := s.QueryOptionalHold(context.Background(), b.Case, cut); e != nil {
		t.Fatal(e)
	}
	if e := s.ReleaseOptionalHold(context.Background(), b.Case, 2, cut); e != nil {
		t.Fatal(e)
	}
	if n, e := s.Sweep(cut); e != nil || n != 1 {
		t.Fatal("release GC", n, e)
	}
	if _, e := s.QueryOptionalHold(context.Background(), b.Case, cut); e == nil {
		t.Fatal("released source read")
	}
}

func bindingSite(entry Entry) domain.ID {
	var p OptionalPayload
	_ = strictjson.Decode(entry.Payload, &p)
	return p.Record.Site
}

func TestOptionalHoldMultipleCasesPartialPruneAndExpiry(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	var p OptionalPayload
	if e := strictjson.Decode(entries[0].Payload, &p); e != nil {
		t.Fatal(e)
	}
	unheld := p.Record
	unheld.ID = domain.NewID()
	if e := s.Write(context.Background(), unheld); e != nil {
		t.Fatal(e)
	}
	b.Until = domain.Time(now.Add(4 * time.Minute).UnixNano())
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	b2 := b
	b2.Case = domain.NewID()
	b2.Until = domain.Time(now.Add(5 * time.Minute).UnixNano())
	if e := s.ReserveOptionalHold(context.Background(), b2, entries, now); e != nil {
		t.Fatal(e)
	}
	cut := now.Add(2 * time.Minute)
	if n, e := s.Sweep(cut); e != nil || n != 1 {
		t.Fatal("partial prune", n, e)
	}
	if e := s.ReleaseOptionalHold(context.Background(), b.Case, 2, cut); e != nil {
		t.Fatal(e)
	}
	if n, e := s.Sweep(cut); e != nil || n != 0 {
		t.Fatal("other case pin ignored", n, e)
	}
	if _, e := s.QueryOptionalHold(context.Background(), b2.Case, cut); e != nil {
		t.Fatal(e)
	}
	if n, e := s.Sweep(now.Add(6 * time.Minute)); e != nil || n != 1 {
		t.Fatal("case expiry GC", n, e)
	}
}

func TestOptionalHoldUncertainSaveStopsGCAndRecovers(t *testing.T) {
	for _, stop := range []string{"hold:sync", "hold:rename"} {
		t.Run(stop, func(t *testing.T) {
			s, key, b, entries, now := optionalHoldFixture(t)
			injected := errors.New("stop")
			s.checkpoint = func(at string) error {
				if at == stop {
					return injected
				}
				return nil
			}
			if e := s.ReserveOptionalHold(context.Background(), b, entries, now); !errors.Is(e, injected) {
				t.Fatal(e)
			}
			if _, e := s.Sweep(now.Add(2 * time.Minute)); e == nil {
				t.Fatal("uncertain hold allowed GC", e)
			}
			if stop == "hold:sync" {
				if e := InspectOptionalStore(s.root, bindingSite(entries[0]), key); !errors.Is(e, store.ErrIncomplete) {
					t.Fatal(e)
				}
			}
			s.checkpoint = nil
			if e := s.ReloadOptionalHolds(); e != nil {
				t.Fatal("same-process recovery", e)
			}
			if n, e := s.Sweep(now.Add(2 * time.Minute)); e != nil || n != 0 {
				t.Fatal(n, e)
			}
			if rows, e := s.QueryOptionalHold(context.Background(), b.Case, now.Add(2*time.Minute)); e != nil || len(rows) != 1 {
				t.Fatal(rows, e)
			}
		})
	}
}

func TestOptionalHoldRejectsCandidateTamperScopeAndStaleRelease(t *testing.T) {
	s, key, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	changed := b
	changed.Board = domain.NewID()
	if e := s.ReserveOptionalHold(context.Background(), changed, entries, now); e == nil {
		t.Fatal("scope changed")
	}
	if e := s.ReleaseOptionalHold(context.Background(), b.Case, 0, now); e == nil {
		t.Fatal("stale release")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.QueryOptionalHold(ctx, b.Case, now); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	path := s.holdFile(b.Case)
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), "127.0.0.1") || strings.Contains(string(raw), "user_agent") {
		t.Fatal("private body in reservation")
	}
	if e := os.WriteFile(path+".pending", []byte("invalid candidate"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := s.ReloadOptionalHolds(); e == nil {
		t.Fatal("invalid candidate accepted")
	}
	if _, e := s.Sweep(now.Add(2 * time.Minute)); e == nil {
		t.Fatal("invalid candidate GC")
	}
	if _, e := os.Stat(path + ".pending"); e != nil {
		t.Fatal("candidate erased", e)
	}
	root := s.root
	s.Close()
	if e := InspectOptionalStore(root, bindingSite(entries[0]), key); e == nil {
		t.Fatal("invalid candidate check")
	}
	if opened, e := OpenOptionalStore(root, bindingSite(entries[0]), key); e == nil {
		opened.Close()
		t.Fatal("invalid candidate startup")
	}
	if _, e := os.Stat(filepath.Join(root, optionalHoldsDir, b.Case.String()+".json.pending")); e != nil {
		t.Fatal(e)
	}
}

func TestOptionalHoldReserveAndSweepSerializes(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.QueryOptionalHold(context.Background(), b.Case, now.Add(2*time.Minute)); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if n, e := s.Sweep(now.Add(2 * time.Minute)); e != nil || n != 0 {
			t.Errorf("held source lost: %d %v", n, e)
		}
	}()
	wg.Wait()
}

// 同一所有者の再読込みで既知予約を欠落/巻戻しさせず、保護のない空状態へ変えない。
func TestOptionalHoldReloadRejectsMissingAndRollback(t *testing.T) {
	for _, mode := range []string{"missing", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			s, _, b, entries, now := optionalHoldFixture(t)
			if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
				t.Fatal(e)
			}
			original, e := os.ReadFile(s.holdFile(b.Case))
			if e != nil {
				t.Fatal(e)
			}
			if mode == "missing" {
				if e = os.Remove(s.holdFile(b.Case)); e != nil {
					t.Fatal(e)
				}
			} else {
				b.Revision++
				b.Until += domain.Time(time.Hour)
				if e = s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(s.holdFile(b.Case), original, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e := s.ReloadOptionalHolds(); e == nil {
				t.Fatal("known reservation replaced", mode)
			}
			if _, e := s.Sweep(now.Add(2 * time.Minute)); e == nil {
				t.Fatal("GC after uncertain reload", mode)
			}
		})
	}
}

// 元HTTPの通常期限が残っていても、満了済み案件予約の期限を後から延長しない。
func TestOptionalHoldExpiredReservationCannotReopen(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	b.Until = domain.Time(now.Add(30 * time.Second).UnixNano())
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	b.Revision++
	b.Until = domain.Time(now.Add(time.Hour).UnixNano())
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now.Add(40*time.Second)); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("expired reservation reopened", e)
	}
}

func TestOptionalHoldCapacityAndCancelledReservation(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := s.ReserveOptionalHold(ctx, b, entries, now); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(s.root, optionalHoldsDir)); !os.IsNotExist(e) {
		t.Fatal("cancel created reservation", e)
	}
	for i := 0; i < MaxOptionalHolds; i++ {
		b.Case = domain.NewID()
		if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
			t.Fatal(i, e)
		}
	}
	b.Case = domain.NewID()
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); !errors.Is(e, ErrOptionalQueryLimit) {
		t.Fatal("capacity exceeded", e)
	}
}

func TestOptionalHoldUncertainReleaseKeepsSourceUntilRecovery(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	injected := errors.New("stop")
	s.checkpoint = func(at string) error {
		if at == "hold:sync" {
			return injected
		}
		return nil
	}
	if e := s.ReleaseOptionalHold(context.Background(), b.Case, 2, now); !errors.Is(e, injected) {
		t.Fatal(e)
	}
	if _, e := s.Sweep(now.Add(2 * time.Minute)); e == nil {
		t.Fatal("uncertain release reclaimed source")
	}
	s.checkpoint = nil
	if e := s.ReloadOptionalHolds(); e != nil {
		t.Fatal(e)
	}
	if n, e := s.Sweep(now.Add(2 * time.Minute)); e != nil || n != 1 {
		t.Fatal("release recovery", n, e)
	}
}

func TestOptionalHoldReceiptOwnsBindingAndSourceIDs(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	receipt, found, e := s.OptionalHoldReceipt(b.Case)
	if e != nil || !found || receipt.Sequence != 1 || receipt.State != "active" || receipt.SHA == (domain.Hash{}) {
		t.Fatal(receipt, found, e)
	}
	receipt.Binding.Operations[0] = domain.NewID()
	receipt.Items[0].Record = domain.NewID()
	again, found, e := s.OptionalHoldReceipt(b.Case)
	if e != nil || !found || again.Binding.Operations[0] != b.Operations[0] || again.Items[0].Record != entries[0].Event.RecordID {
		t.Fatal("receipt alias", again, found, e)
	}
	if e := s.ReleaseOptionalHold(context.Background(), b.Case, 2, now); e != nil {
		t.Fatal(e)
	}
	released, found, e := s.OptionalHoldReceipt(b.Case)
	if e != nil || !found || released.Sequence != 2 || released.State != "released" || released.SHA == again.SHA {
		t.Fatal(released, found, e)
	}
}

// 保存不明の予約は、新しい所有者の起動でも候補を採用してからGCを再開する。
func TestOptionalHoldRestartFromDurableCandidate(t *testing.T) {
	for _, stop := range []string{"hold:sync", "hold:rename"} {
		t.Run(stop, func(t *testing.T) {
			s, key, b, entries, now := optionalHoldFixture(t)
			injected := errors.New("stop")
			s.checkpoint = func(at string) error {
				if at == stop {
					return injected
				}
				return nil
			}
			if e := s.ReserveOptionalHold(context.Background(), b, entries, now); !errors.Is(e, injected) {
				t.Fatal(e)
			}
			root, site := s.root, bindingSite(entries[0])
			s.Close()
			reopened, e := OpenOptionalStore(root, site, key)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if n, e := reopened.Sweep(now.Add(2 * time.Minute)); e != nil || n != 0 {
				t.Fatal("restart lost pin", n, e)
			}
			if rows, e := reopened.QueryOptionalHold(context.Background(), b.Case, now.Add(2*time.Minute)); e != nil || len(rows) != 1 {
				t.Fatal(rows, e)
			}
			if _, e := os.Stat(reopened.holdFile(b.Case) + ".pending"); !os.IsNotExist(e) {
				t.Fatal("candidate not finalized", e)
			}
		})
	}
}

// 複数案件が同じ原本を共有しても、期待SHA/seq/元期限が違う予約を同じ検証済み原本へまとめない。
func TestOptionalHoldSharedSourceValidationRejectsConflictingMetadata(t *testing.T) {
	for _, change := range []string{"hash", "sequence", "expiry"} {
		t.Run(change, func(t *testing.T) {
			s, _, b, entries, now := optionalHoldFixture(t)
			if e := s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
				t.Fatal(e)
			}
			second := b
			second.Case = domain.NewID()
			if e := s.ReserveOptionalHold(context.Background(), second, entries, now); e != nil {
				t.Fatal(e)
			}
			if e := s.validateOptionalHoldSources(domain.Time(now.UnixNano())); e != nil {
				t.Fatal(e)
			}
			broken := s.holds[second.Case]
			broken.payload.Items = slices.Clone(broken.payload.Items)
			switch change {
			case "hash":
				broken.payload.Items[0].SHA[0] ^= 1
			case "sequence":
				broken.payload.Items[0].Sequence++
			case "expiry":
				broken.payload.Items[0].Expires++
			}
			s.holds[second.Case] = broken
			if e := s.validateOptionalHoldSources(domain.Time(now.UnixNano())); !errors.Is(e, store.ErrCorrupt) {
				t.Fatal("conflicting source metadata reused verification", e)
			}
		})
	}
}
