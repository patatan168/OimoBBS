// 実元正本のcarry削除と停止後再起動、署名片側欠落の非変更拒否を検査する。
package bootstrap

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func carryRows(state store.ControlState) int {
	n := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "dedup_carry:") || strings.HasPrefix(name, "rate_carry:") {
			n++
		}
	}
	return n
}

func TestBodyCarryErasureRepositoryPagesAndRestart(t *testing.T) {
	cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	before := carryRows(r.posting[owner].deletions[key].State())
	if before < 2 {
		t.Fatal("fixture needs multiple carry rows for partial recovery", before)
	}
	n, e := r.ReclaimExpiredBodyCarry(t.Context(), owner, key, 1)
	if e != nil || n != 1 || carryRows(r.posting[owner].deletions[key].State()) != before-1 {
		t.Fatal("bounded row removal", n, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal("partial erasure reopen", e)
	}
	defer reopened.Close()
	assertCarrySourceSnapshot(t, filepath.Join(cfg.DataDir, "expiry", owner.String(), fmt.Sprint(key)), owner, key)
	finishCarryErasure(t, reopened, owner, key)
}

// finishCarryErasure は起動時の自動回収後に元行がなく、手動再送も無変更であることを確認する。
func finishCarryErasure(t *testing.T, reopened *Repository, owner domain.ID, key uint64) {
	t.Helper()
	assertCarryRateCount(t, reopened.posting[owner], key, 0)
	n, e := reopened.ReclaimExpiredBodyCarry(t.Context(), owner, key, 128)
	if e != nil || n != 0 || carryRows(reopened.posting[owner].deletions[key].State()) != 0 {
		t.Fatal("remaining erasure", n, e)
	}
	if n, e = reopened.ReclaimExpiredBodyCarry(t.Context(), owner, key, 128); e != nil || n != 0 {
		t.Fatal("idempotent erasure", n, e)
	}
}

func TestBodyCarryErasureSourceAndPageStopResume(t *testing.T) {
	for _, stage := range []string{"carry_erasure:source", "carry_erasure:rows"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
			stop := errors.New("interrupted carry erasure")
			b := r.posting[owner]
			b.deletionCheckpoint = func(s string) error {
				if s == stage {
					return stop
				}
				return nil
			}
			if _, e := r.ReclaimExpiredBodyCarry(t.Context(), owner, key, 1); !errors.Is(e, stop) {
				t.Fatal("stop not reached", e)
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
			if e != nil {
				t.Fatal("stopped erasure reopen", e)
			}
			defer reopened.Close()
			if _, e = reopened.ReclaimExpiredBodyCarry(t.Context(), owner, key, 128); e != nil {
				t.Fatal("resume", e)
			}
			if carryRows(reopened.posting[owner].deletions[key].State()) != 0 {
				t.Fatal("resume left carry rows")
			}
		})
	}
}

func TestBodyCarryErasureRejectsUnregisteredOrMissingSeal(t *testing.T) {
	_, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	if _, e := r.ReclaimExpiredBodyCarry(t.Context(), owner, key, 1); e != nil {
		t.Fatal(e)
	}
	b := r.posting[owner]
	state := b.deletions[key].State()
	proof, e := readBodyReclamation(state, owner, key, b.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	if e = inspectCarryErasureReference(58, b.control.State(), state, owner, key); e == nil {
		t.Fatal("reader58 accepted erasure")
	}
	if e = inspectCarryErasureReference(59, store.ControlState{Rows: map[string]store.ControlRow{}}, state, owner, key); e == nil {
		t.Fatal("missing board registration accepted")
	}
	copy := store.ControlState{Rows: map[string]store.ControlRow{}}
	for name, row := range state.Rows {
		copy.Rows[name] = row
	}
	delete(copy.Rows, "reclamation:carry")
	if _, e = readBodyCarry(copy, *proof); e == nil {
		t.Fatal("missing original seal accepted")
	}
	delete(copy.Rows, "reclamation:carry_retirement")
	copy.Rows["reclamation:carry"] = state.Rows["reclamation:carry"]
	if _, e = readBodyCarry(copy, *proof); e == nil {
		t.Fatal("unsigned missing rows accepted")
	}
}

func TestBodyCarryErasureInvalidLimitDoesNotMutate(t *testing.T) {
	cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	before := requiredStartupFiles(t, cfg.DataDir)
	if n, e := r.ReclaimExpiredBodyCarry(t.Context(), owner, key, 129); n != 0 || e == nil {
		t.Fatal("invalid limit accepted", n, e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("invalid limit changed files")
	}
}

func TestBodyCarryErasureThenOriginalGCAndRestart(t *testing.T) {
	cfg, r, owner, key, day, identity := requiredReclaimRepositoryFixture(t, true)
	if _, e := r.ReclaimExpiredBodyCarry(t.Context(), owner, key, 128); e != nil {
		t.Fatal(e)
	}
	requiredReclaimDraft(t, r, owner)
	if n, e := r.ReclaimRequiredOriginals(t.Context(), owner, key, day, []evidence.RequiredPostingIdentity{identity}); e != nil || n != 2 {
		t.Fatal("original GC after row erasure", n, e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal("body/original/carry erased reopen", e)
	}
	defer reopened.Close()
	assertCarryRateCount(t, reopened.posting[owner], key, 0)
	if carryRows(reopened.posting[owner].deletions[key].State()) != 0 {
		t.Fatal("recovery resurrected carry rows")
	}
}

func TestBodyCarryErasureOldBoardPrefixRefusedBeforeRepair(t *testing.T) {
	cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	path := filepath.Join(cfg.DataDir, "boards", owner.String(), "control")
	old := requiredStartupFiles(t, path)
	if _, e := r.ReclaimExpiredBodyCarry(t.Context(), owner, key, 128); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	restoreCheckpointSource(t, path, old)
	assertCarryUnsafeStartup(t, cfg, "old_board_prefix")
}
