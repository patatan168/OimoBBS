// 捕捉済みcopyと元carryの圧縮/旧WAL回収が重なっても固定境界を失わないことを検査する。
package bootstrap

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func TestBodyCarryBackupCopiesPinnedWALAfterPeriodicReclaim(t *testing.T) {
	cfg, r, owner, key, day, identity := requiredReclaimRepositoryFixture(t, true)
	if _, e := r.ReclaimExpiredBodyCarry(t.Context(), owner, key, 1); e != nil {
		t.Fatal(e)
	}
	requiredReclaimDraft(t, r, owner)
	if n, e := r.ReclaimRequiredOriginals(t.Context(), owner, key, day, []evidence.RequiredPostingIdentity{identity}); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	expected := r.posting[owner].deletions[key].State()
	pin, e := r.PinBoardBackup(t.Context(), owner, OnlineBackupGroupOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	output := onlineOutput(t, "carry-overlap")
	reached := false
	cut, e := pin.copy(t.Context(), output, func(index int) error {
		if pin.parts[index].kind != "deletion" {
			return nil
		}
		reached = true
		runCarryMaintenance(t, r)
		assertCarrySourceSnapshot(t, filepath.Join(cfg.DataDir, "expiry", owner.String(), fmt.Sprint(key)), owner, key)
		return nil
	})
	if e != nil || !reached {
		t.Fatal("overlap copy", reached, e)
	}
	assertCarryPinnedCopy(t, r, output, owner, key, expected, cut)
}

// assertCarryPinnedCopy は固定元の再生照合と全体予約の解放を確認する。
func assertCarryPinnedCopy(t *testing.T, r *Repository, output string, owner domain.ID, key uint64, expected store.ControlState, cut OnlineBackupGroupCapture) {
	t.Helper()
	copied := filepath.Join(output, "deletion", owner.String(), fmt.Sprint(key))
	state, e := inspectDeletionControl(copied, owner, key)
	if e != nil || !reflect.DeepEqual(state, expected) {
		t.Fatal("pinned prefix lost", e)
	}
	control, e := store.OpenControlWithValidators(filepath.Join(output, "board", owner.String(), "control"), 2, owner, 0, validateBoardValue, snapshotBoardValue)
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	if e = validateOnlineBoardCopy(t.Context(), output, r.posting[owner], control, cut.Captures); e != nil {
		t.Fatal("fixed copy validation", e)
	}
	r.packResourcesMu.Lock()
	held := r.backupActive || r.backupReserved != 0
	r.packResourcesMu.Unlock()
	if held {
		t.Fatal("copy leaked backup reservation")
	}
}

// TestBodyCarryBackupStillRejectsExpiredOriginal は回収証跡の例外が現用原本へ広がらないことを検査する。
func TestBodyCarryBackupStillRejectsExpiredOriginal(t *testing.T) {
	cfg, r, owner, _, _, _ := requiredReclaimRepositoryFixture(t, true)
	before := requiredStartupFiles(t, cfg.DataDir)
	output := onlineOutput(t, "expired-original")
	cut, e := r.CopyBoardBackup(t.Context(), owner, output, OnlineBackupGroupOptions{})
	if e != nil {
		if !strings.Contains(e.Error(), "thread expired during group copy") {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
			t.Fatal("expired copy changed source")
		}
		return
	}
	control, e := store.OpenControlWithValidators(filepath.Join(output, "board", owner.String(), "control"), 2, owner, 0, validateBoardValue, snapshotBoardValue)
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	e = validateOnlineBoardCopy(t.Context(), output, r.posting[owner], control, cut.Captures)
	if e == nil || !strings.Contains(e.Error(), "expired evidence requires maintenance") {
		t.Fatal("expired original accepted", e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("copy validation changed source")
	}
}
