// 実署名案件の終端参照採用・起動/周期の元解除と再起動後の連続性を検査する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

// terminalUnreflectedOptionalFixture は元更新seq2を未保存のまま案件取消を署名する停止点を作る。
func terminalUnreflectedOptionalFixture(t *testing.T) (Config, *Repository, disclosure.Case) {
	t.Helper()
	cfg, r, c, entries, _ := optionalHeldCaseProductFixture(t)
	r.mu.Lock()
	defer r.mu.Unlock()
	b, e := r.evidenceCases.HTTPReservationBinding(c, time.Now())
	if e == nil {
		e = r.optionalStore.ReserveOptionalHold(context.Background(), b, entries, time.Now())
	}
	if e != nil {
		t.Fatal(e)
	}
	c, e = r.evidenceCases.Release(c.ID, c.Creator, c.ETag(), "terminal-cancel", "取消", time.Now())
	if e != nil || c.State != "closed" || c.HTTP.Reservation.Sequence != 1 {
		t.Fatal(c, e)
	}
	return cfg, r, c
}

// assertTerminalOptionalReconciled は元解除の直前参照が案件へ署名され、現在解除と連続することを検査する。
func assertTerminalOptionalReconciled(t *testing.T, r *Repository, id domain.ID) disclosure.Case {
	t.Helper()
	r.mu.Lock()
	c, e := r.evidenceCases.Get(id)
	r.mu.Unlock()
	if e != nil || c.State != "closed" || c.HTTP.Reservation.Sequence != 2 {
		t.Fatal("unsaved next not adopted", c, e)
	}
	latest, e := r.optionalStore.CheckOptionalHoldReceipt(*c.HTTP.Reservation)
	if e != nil || latest.State != "released" || latest.Sequence != 3 || c.HTTP.Released == nil || c.HTTP.Released.SHA != latest.SHA {
		t.Fatal("release chain", latest, e)
	}
	if _, e = r.optionalStore.QueryOptionalHold(context.Background(), id, time.Now()); e == nil {
		t.Fatal("released original query allowed")
	}
	return c
}

func TestOptionalTerminalHoldReconcileThenRestart(t *testing.T) {
	cfg, r, c := terminalUnreflectedOptionalFixture(t)
	r.mu.Lock()
	_, e := r.reconcileTerminalOptionalHold(context.Background(), c, r.optionalStore)
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	saved := assertTerminalOptionalReconciled(t, r, c.ID)
	if e = r.reconcileTerminalOptionalHolds(context.Background()); e != nil {
		t.Fatal("terminal replay", e)
	}
	if got := assertTerminalOptionalReconciled(t, r, c.ID); got.ETag() != saved.ETag() {
		t.Fatal("terminal replay added audit")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reconciled release rejected after restart", e)
	}
	defer reopened.Close()
	assertTerminalOptionalReconciled(t, reopened, c.ID)
}

func TestOptionalTerminalHoldReconcileAtStartup(t *testing.T) {
	cfg, r, c := terminalUnreflectedOptionalFixture(t)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	assertTerminalOptionalReconciled(t, reopened, c.ID)
}

func TestOptionalTerminalHoldReconcileDuringMaintenance(t *testing.T) {
	_, r, c := terminalUnreflectedOptionalFixture(t)
	r.optionalCancel()
	<-r.optionalDone
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	r.optionalCancel, r.optionalDone = cancel, done
	processed := make(chan struct{}, 1)
	r.optionalLossMu.Lock()
	r.optionalLossBeforeSnapshot = func() {
		select {
		case processed <- struct{}{}:
		default:
		}
	}
	r.optionalLossMu.Unlock()
	go r.runOptionalLogMaintenance(ctx, r.optionalStore, ticks, done)
	ticks <- time.Now()
	select {
	case <-processed:
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance did not finish")
	}
	cancel()
	<-done
	r.optionalLossMu.Lock()
	r.optionalLossBeforeSnapshot = nil
	r.optionalLossMu.Unlock()
	assertTerminalOptionalReconciled(t, r, c.ID)
}

func TestOptionalTerminalHoldReconcilePreservesLastPostingSlot(t *testing.T) {
	_, r, c := terminalUnreflectedOptionalFixture(t)
	r.packResourcesMu.Lock()
	oldProbe := r.packSpace
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: (1 << 30) + postingReservationBytes}, nil
	}
	r.packResourcesMu.Unlock()
	e := r.reconcileTerminalOptionalHolds(context.Background())
	if !errors.Is(e, ErrPostingCapacity) {
		t.Fatal("cleanup consumed last posting slot", e)
	}
	r.mu.Lock()
	current, getError := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	if getError != nil || current.ETag() != c.ETag() {
		t.Fatal("capacity rejection changed signed reference", current, getError)
	}
	ref, _, getError := r.optionalStore.OptionalHoldReceipt(c.ID)
	if getError != nil || ref.State != "active" || ref.Sequence != 2 {
		t.Fatal("capacity rejection released source", ref, getError)
	}
	r.packResourcesMu.Lock()
	reserved := r.postReserved
	r.packSpace = oldProbe
	r.packResourcesMu.Unlock()
	if reserved != 0 {
		t.Fatal("cleanup reservation leaked", reserved)
	}
	if e = r.reconcileTerminalOptionalHolds(context.Background()); e != nil {
		t.Fatal("cleanup capacity recovery", e)
	}
	assertTerminalOptionalReconciled(t, r, c.ID)
}

func TestOptionalTerminalHoldMissingCompletedCopyKeepsOriginal(t *testing.T) {
	cfg, r, c, entries, _ := optionalHeldCaseProductFixture(t)
	r.mu.Lock()
	ref := *c.HTTP.Reservation
	c, e := r.evidenceCases.ResumeHTTPReserved(c.ID, c.Creator, c.ETag(), entries, ref, time.Now(), func() error {
		return r.awaitOptionalHoldOwner(func() error {
			current, checkError := r.optionalStore.CheckOptionalHoldReceipt(ref)
			if checkError != nil {
				return checkError
			}
			if current.State != "active" || current.SHA != ref.SHA {
				return store.ErrIncomplete
			}
			return nil
		})
	})
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	copyPath := filepath.Join(cfg.DataDir, "cases", c.ID.String(), "http", c.HTTP.Items[0].Record.String()+".json")
	if e = os.Remove(copyPath); e != nil {
		t.Fatal(e)
	}
	if e = r.reconcileTerminalOptionalHolds(context.Background()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("missing completed copy allowed release", e)
	}
	latest, _, e := r.optionalStore.OptionalHoldReceipt(c.ID)
	if e != nil || latest.State != "active" || latest.SHA != ref.SHA {
		t.Fatal("missing copy lost source lease", latest, e)
	}
	original, e := r.optionalStore.QueryOptionalHold(context.Background(), c.ID, time.Now())
	if e != nil || len(original) != 1 || original[0].Event.EventSHA != entries[0].Event.EventSHA {
		t.Fatal("protected original lost", original, e)
	}
}
