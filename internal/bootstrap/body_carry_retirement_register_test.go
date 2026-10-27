// 実製品の満了先行登録、再送、板復旧と不完全元の非変更拒否を検査する。
package bootstrap

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestBodyCarryRetirementRepositoryRegisterAndReopen(t *testing.T) {
	cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	b := r.posting[owner]
	assertCarryRateCount(t, b, key, 1)
	if e := r.RegisterExpiredBodyCarry(t.Context(), owner, key); e != nil {
		t.Fatal(e)
	}
	assertCarryRateCount(t, b, key, 0)
	name := "carry_retirement:" + fmt.Sprint(key)
	first := b.control.State().Rows[name]
	if len(first.Value) == 0 {
		t.Fatal("missing durable anchor")
	}
	assertCarryRetirementReader(t, r)
	if e := r.RegisterExpiredBodyCarry(t.Context(), owner, key); e != nil {
		t.Fatal("retry", e)
	}
	if !reflect.DeepEqual(first, b.control.State().Rows[name]) {
		t.Fatal("retry changed fixed signature")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := checkLockedPosting(cfg, false, true); e != nil {
		t.Fatal("check", e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal("reopen", e)
	}
	defer reopened.Close()
	assertCarryRateCount(t, reopened.posting[owner], key, 0)
	if !reflect.DeepEqual(first, reopened.posting[owner].control.State().Rows[name]) {
		t.Fatal("reopen changed anchor")
	}
}

func assertCarryRetirementReader(t *testing.T, r *Repository) {
	t.Helper()
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil || site.MinimumReader != 58 {
		t.Fatal("minimum reader", site.MinimumReader, e)
	}
}

func assertCarryRateCount(t *testing.T, b *postingBoard, key uint64, want int) {
	t.Helper()
	_, e := b.worker.Submit(t.Context(), func() (any, error) {
		rows, e := b.threads[key].RateHistory()
		if e == nil && len(rows) != want {
			t.Errorf("rate history: got %d, want %d", len(rows), want)
		}
		return nil, e
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestBodyCarryRetirementRepositoryRejectsIncomplete(t *testing.T) {
	cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, false)
	before := requiredStartupFiles(t, cfg.DataDir)
	if e := r.RegisterExpiredBodyCarry(t.Context(), owner, key); e == nil {
		t.Fatal("incomplete public body accepted")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("failed preflight changed storage")
	}
	if e := r.RegisterExpiredBodyCarry(t.Context(), domain.NewID(), key); e == nil {
		t.Fatal("unknown owner accepted")
	}
}

func TestBodyCarryRetirementRepositoryOriginalGC(t *testing.T) {
	cfg, r, owner, key, day, identity := requiredReclaimRepositoryFixture(t, true)
	if e := r.RegisterExpiredBodyCarry(t.Context(), owner, key); e != nil {
		t.Fatal(e)
	}
	requiredReclaimDraft(t, r, owner)
	if n, e := r.ReclaimRequiredOriginals(t.Context(), owner, key, day, []evidence.RequiredPostingIdentity{identity}); e != nil || n != 2 {
		t.Fatal("original GC after carry retirement", n, e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal("retired originals reopen", e)
	}
	defer reopened.Close()
	assertCarryRateCount(t, reopened.posting[owner], key, 0)
}

func TestBodyCarryRetirementRepositoryRejectsUnsafeStartup(t *testing.T) {
	for _, mode := range []string{"future_clock", "missing_body"} {
		t.Run(mode, func(t *testing.T) {
			cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
			b := r.posting[owner]
			if mode == "future_clock" {
				_, e := b.worker.Submit(t.Context(), func() (any, error) {
					future := time.Now().Add(time.Hour)
					b.clock = func() time.Time { return future }
					return nil, nil
				})
				if e != nil {
					t.Fatal(e)
				}
			}
			if e := r.RegisterExpiredBodyCarry(t.Context(), owner, key); e != nil {
				t.Fatal(e)
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			if mode == "missing_body" {
				if e := os.RemoveAll(filepath.Join(cfg.DataDir, "expiry", owner.String(), fmt.Sprint(key))); e != nil {
					t.Fatal(e)
				}
			}
			assertCarryUnsafeStartup(t, cfg, mode)
		})
	}
}

func assertCarryUnsafeStartup(t *testing.T, cfg Config, mode string) {
	t.Helper()
	before := requiredStartupFiles(t, cfg.DataDir)
	_, e := checkLockedPosting(cfg, false, true)
	if e == nil || mode == "future_clock" && !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("unsafe check accepted", mode, e)
	}
	opened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if opened != nil {
		_ = opened.Close()
		t.Fatal("unsafe repository opened", mode)
	}
	if e == nil || mode == "future_clock" && !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("unsafe startup accepted", mode, e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("unsafe startup changed files")
	}
}

func TestBodyCarryRetirementAnchorRequiresReaderAndImmutableRow(t *testing.T) {
	_, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	if e := r.RegisterExpiredBodyCarry(t.Context(), owner, key); e != nil {
		t.Fatal(e)
	}
	b := r.posting[owner]
	row := b.control.State().Rows["carry_retirement:"+fmt.Sprint(key)]
	if e := validateBoardValue("carry_retirement", fmt.Sprint(key), row.Value, row.Value); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("immutable row updated", e)
	}
	if e := validateBoardValue("carry_retirement", fmt.Sprint(key), row.Value, []byte("null")); e == nil {
		t.Fatal("immutable row deleted")
	}
	if e := validateBoardValue("carry_retirement", fmt.Sprint(key+1), nil, row.Value); e == nil {
		t.Fatal("another key accepted")
	}
	e := inspectBodyCarryRetirementAnchors(Config{}, siteState{MinimumReader: 57}, persistedBoard{info: BoardInfo{ID: owner}, control: b.control.State()}, b.key.Public().(ed25519.PublicKey))
	if !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("reader57 accepted anchor", e)
	}
}
