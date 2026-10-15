// 実Repositoryの有効化/周期段階/耐久再開と、進捗・独立保存先の拒否を検証する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func requiredGCJobForTest(t *testing.T, r *Repository) requiredGCState {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	_, job, e := r.requiredGCJob(time.Now())
	if e != nil || job == nil {
		t.Fatal(job, e)
	}
	return *job
}

func TestRequiredGCJobReopensWhenManualGCPrecedesCursorSave(t *testing.T) {
	cfg, r, id, key, day, identity := requiredReclaimRepositoryFixture(t, true)
	if e := r.EnableRequiredOriginalReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	requiredGCSelectScopeForTest(t, r)
	saved := requiredGCJobForTest(t, r)
	if n, e := r.ReclaimRequiredOriginals(t.Context(), id, key, day, []evidence.RequiredPostingIdentity{identity}); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	if !reflect.DeepEqual(saved, requiredGCJobForTest(t, r)) {
		t.Fatal("manual GC changed automatic cursor")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if job := requiredGCJobForTest(t, reopened); job.Round != saved.Round+1 || job.Day != 0 || job.After != 0 {
		t.Fatal("unreflected GC was not resumed", job)
	}
}

func requiredGCSelectScopeForTest(t *testing.T, r *Repository) {
	t.Helper()
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	_, _, e := r.stepRequiredGCJobLocked(t.Context())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
}

func TestRequiredGCJobBadSignedScopeCursorFailsBeforeRepair(t *testing.T) {
	cfg, r, _, _, _, _ := requiredReclaimRepositoryFixture(t, true)
	if e := r.EnableRequiredOriginalReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	if n, e := r.SweepRequiredOriginals(t.Context()); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	job := requiredGCJobForTest(t, r)
	job.After, job.Day, job.At = 2, 0, domain.Time(time.Now().UnixNano())
	r.mu.Lock()
	e := r.saveRequiredGCJob(job, "required_original_gc_progress")
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	if opened, e := OpenPostingRepository(cfg, postingCaptureFixture); !errors.Is(e, store.ErrCorrupt) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("cursor exceeded signed public sequence", e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("invalid cursor triggered repair")
	}
}

func TestRequiredGCJobEnableSweepReopenAndPause(t *testing.T) {
	cfg, r, id, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	if e := r.EnableRequiredOriginalReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	checkRequiredGCInitialJob(t, r)
	if n, e := r.SweepRequiredOriginals(t.Context()); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	job := checkRequiredGCPrunedJob(t, r, id, key)
	checkRequiredGCDisableAndReenable(t, r, job)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	next := requiredGCJobForTest(t, reopened)
	if next.Round <= job.Round || next.Day != 0 || next.After != 0 {
		t.Fatal("startup did not resume saved completed window", next)
	}
}

func checkRequiredGCInitialJob(t *testing.T, r *Repository) {
	t.Helper()
	initial := requiredGCJobForTest(t, r)
	if !initial.Enabled || initial.Round != 1 || initial.Board != nil {
		t.Fatal(initial)
	}
}

func checkRequiredGCPrunedJob(t *testing.T, r *Repository, id domain.ID, key uint64) requiredGCState {
	t.Helper()
	job := requiredGCJobForTest(t, r)
	if job.boardID() != id || uint64(job.Key) != key || job.Day == 0 || job.Proof == (domain.Hash{}) || r.postReserved != 0 {
		t.Fatal(job)
	}
	return job
}

func checkRequiredGCDisableAndReenable(t *testing.T, r *Repository, saved requiredGCState) {
	t.Helper()
	if e := r.DisableRequiredOriginalReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	before := r.site.State().Seq
	if n, e := r.SweepRequiredOriginals(t.Context()); e != nil || n != 0 || r.site.State().Seq != before {
		t.Fatal("disabled sweep mutated", n, e)
	}
	if e := r.EnableRequiredOriginalReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	after := requiredGCJobForTest(t, r)
	after.At = saved.At
	if !reflect.DeepEqual(after, saved) {
		t.Fatal("enable reset progress", after, saved)
	}
}

func TestRequiredGCJobCapacityFailureKeepsWindow(t *testing.T) {
	cfg, r, _, _, _, _ := requiredReclaimRepositoryFixture(t, true)
	if e := r.EnableRequiredOriginalReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	_, _, e := r.stepRequiredGCJobLocked(t.Context())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	saved := requiredGCJobForTest(t, r)
	r.backupReserved = ^uint64(0) - (8 << 20)
	defer func() { r.backupReserved = 0 }()
	if n, e := r.SweepRequiredOriginals(t.Context()); !errors.Is(e, ErrPostingCapacity) || n != 0 {
		t.Fatal(n, e)
	}
	if !reflect.DeepEqual(saved, requiredGCJobForTest(t, r)) || !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) || r.postReserved != 0 {
		t.Fatal("failed GC advanced or mutated")
	}
}

func TestRequiredGCJobMissingIndependentCarryKeepsOriginals(t *testing.T) {
	cfg, r, id, key, day, identity := requiredReclaimRepositoryFixture(t, true)
	path := filepath.Join(cfg.DataDir, "expiry", id.String(), strconv.FormatUint(key, 10))
	saved := filepath.Join(cfg.DataDir, "expiry", id.String(), ".saved-independent-carry")
	if e := os.Rename(path, saved); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = os.Rename(saved, path) }()
	before := requiredStartupFiles(t, cfg.DataDir)
	if n, e := r.ReclaimRequiredOriginals(t.Context(), id, key, day, []evidence.RequiredPostingIdentity{identity}); e == nil || n != 0 {
		t.Fatal("memory-only carry allowed GC", n, e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("missing independent carry changed originals")
	}
}

func TestRequiredGCDisabledEmptyAndCancelledAreNonMutating(t *testing.T) {
	cfg, r, _, _, _, _ := requiredReclaimRepositoryFixture(t, true)
	before := requiredStartupFiles(t, cfg.DataDir)
	if n, e := r.SweepRequiredOriginals(t.Context()); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := r.SweepRequiredOriginals(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("disabled/cancelled GC mutated")
	}
}

func TestRequiredGCJobPeriodicRetentionEntryReclaims(t *testing.T) {
	_, r, id, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	if e := r.EnableRequiredOriginalReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	e := r.reconcileRequiredRetentionLocked(t.Context())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	_ = checkRequiredGCPrunedJob(t, r, id, key)
}

func TestRequiredGCJobMissingPhysicalSourceKeepsWindow(t *testing.T) {
	cfg, r, id, _, day, _ := requiredReclaimRepositoryFixture(t, true)
	if e := r.EnableRequiredOriginalReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	requiredGCSelectScopeForTest(t, r)
	savedJob := requiredGCJobForTest(t, r)
	path := filepath.Join(cfg.DataDir, "evidence", id.String(), strconv.FormatUint(day, 10))
	saved := filepath.Join(t.TempDir(), "saved-originals")
	if e := os.Rename(path, saved); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = os.Rename(saved, path) }()
	before := requiredStartupFiles(t, cfg.DataDir)
	if n, e := r.SweepRequiredOriginals(t.Context()); e == nil || n != 0 {
		t.Fatal("memory-only source allowed GC", n, e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) || !reflect.DeepEqual(savedJob, requiredGCJobForTest(t, r)) || r.postReserved != 0 {
		t.Fatal("missing source advanced or mutated")
	}
}
