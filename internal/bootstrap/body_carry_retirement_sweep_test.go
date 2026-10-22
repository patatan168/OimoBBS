// 実保守入口での自動登録、期限前保留、保存後時計逆行の板停止を検査する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func runCarryMaintenance(t *testing.T, r *Repository) {
	t.Helper()
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	e := r.reconcileRequiredRetentionLocked(t.Context())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
}

func TestBodyCarryRetirementMaintenanceRegisterAndRestart(t *testing.T) {
	cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	runCarryMaintenance(t, r)
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil || site.MinimumReader != bodyCarrySnapshotReader {
		t.Fatal("maintenance reader", site.MinimumReader, e)
	}
	path := filepath.Join(cfg.DataDir, "expiry", owner.String(), fmt.Sprint(key))
	assertCarrySourceSnapshot(t, path, owner, key)
	b := r.posting[owner]
	assertCarryRateCount(t, b, key, 0)
	name := "carry_retirement:" + fmt.Sprint(key)
	first := b.control.State().Rows[name]
	if len(first.Value) == 0 {
		t.Fatal("maintenance omitted registration")
	}
	runCarryMaintenance(t, r)
	if !reflect.DeepEqual(first, b.control.State().Rows[name]) {
		t.Fatal("maintenance changed fixed signature")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	assertCarryRateCount(t, reopened.posting[owner], key, 0)
}

// freshHiddenCarryFixture は実HTTP投稿と管理hideから期限前の完成carryを作る。
func freshHiddenCarryFixture(t *testing.T) (Config, *Repository, domain.ID, uint64) {
	t.Helper()
	cfg, r := adminFixture(t)
	t.Cleanup(func() { _ = r.Close() })
	board, e := r.CreateBoard(t.Context(), "carry", "満了前")
	if e != nil {
		t.Fatal(e)
	}
	if e = r.EnablePublicBodyReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	form := formServer(t, r, siteID(r.site.State()), board.ID)
	defer form.Close()
	created, e := sendForm(form, url.Values{"bbs": {"carry"}, "subject": {"期限前"}, "MESSAGE": {"保存を維持"}, "oimo_request_id": {"carry-before-expiry-0001"}})
	if e != nil || !created.Accepted {
		t.Fatal(created, e)
	}
	hideBodyFixture(t, r, board.ID, created.Key)
	if e = r.ReclaimPublicBodies(t.Context(), 1); e != nil {
		t.Fatal(e)
	}
	return cfg, r, board.ID, created.Key
}

func TestBodyCarryRetirementMaintenanceKeepsUnexpiredCarry(t *testing.T) {
	cfg, r, owner, key := freshHiddenCarryFixture(t)
	runCarryMaintenance(t, r)
	b := r.posting[owner]
	assertCarryRateCount(t, b, key, 1)
	if _, found := b.control.State().Rows["carry_retirement:"+fmt.Sprint(key)]; found {
		t.Fatal("unexpired carry retired")
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	if e := r.RegisterExpiredBodyCarry(t.Context(), owner, key); !errors.Is(e, app.ErrBodyCarryNotExpired) {
		t.Fatal("unexpired manual registration", e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("unexpired registration changed files")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	assertCarryRateCount(t, reopened.posting[owner], key, 1)
}

func TestBodyCarryRetirementPersistClockFailureStopsBoard(t *testing.T) {
	_, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	if _, e := r.enableStorageReader(t.Context(), bodyCarryRetirementReader, "carry_failure_test"); e != nil {
		t.Fatal(e)
	}
	b := r.posting[owner]
	_, e := b.worker.Submit(t.Context(), func() (any, error) {
		future := time.Now().Add(time.Hour)
		b.clock = func() time.Time { return future }
		v, e := b.prepareCarryRetirement(t.Context(), key)
		if e != nil {
			return nil, e
		}
		b.clock = time.Now
		return nil, b.persistCarryRetirement(v)
	})
	if !errors.Is(e, evidence.ErrRetirementClock) || !b.stopped {
		t.Fatal("durable retirement failure left board available", e)
	}
	if len(b.control.State().Rows["carry_retirement:"+fmt.Sprint(key)].Value) == 0 {
		t.Fatal("failure was before durable anchor")
	}
}

func TestBodyCarryRetirementMaintenanceCancelledIsNonMutating(t *testing.T) {
	cfg, r, _, _, _, _ := requiredReclaimRepositoryFixture(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := requiredStartupFiles(t, cfg.DataDir)
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	e := r.reconcileRequiredRetentionLocked(ctx)
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if !errors.Is(e, context.Canceled) || !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("cancelled maintenance changed files", e)
	}
}

func TestBodyCarryRetirementMaintenanceOnePerRun(t *testing.T) {
	_, r, firstOwner, firstKey, _, _ := requiredReclaimRepositoryFixture(t, true)
	info, e := r.CreateBoard(t.Context(), "carrytwo", "二件目")
	if e != nil {
		t.Fatal(e)
	}
	secondKey := postExpiredCarryFixture(t, r.posting[info.ID])
	if e = r.ReclaimPublicBodies(t.Context(), 1); e != nil {
		t.Fatal(e)
	}
	runCarryMaintenance(t, r)
	first := len(r.posting[firstOwner].control.State().Rows["carry_retirement:"+fmt.Sprint(firstKey)].Value) != 0
	second := len(r.posting[info.ID].control.State().Rows["carry_retirement:"+fmt.Sprint(secondKey)].Value) != 0
	if first == second {
		t.Fatal("first maintenance must register exactly one of two boards", first, second)
	}
	runCarryMaintenance(t, r)
	assertCarryRateCount(t, r.posting[firstOwner], firstKey, 0)
	assertCarryRateCount(t, r.posting[info.ID], secondKey, 0)
}

// postExpiredCarryFixture は別板にも古い実投稿を保存し、同時候補を作る。
func postExpiredCarryFixture(t *testing.T, b *postingBoard) uint64 {
	t.Helper()
	frame, at := expiredRequiredFrame(t)
	value, e := b.worker.Submit(t.Context(), func() (any, error) {
		b.clock = func() time.Time { return time.Unix(0, int64(at)) }
		defer func() { b.clock = time.Now }()
		return b.post(0, frame, []byte(`{"fixture":true}`)), nil
	})
	if e != nil || value.(RepositoryPostingResult).Status != store.Durable {
		t.Fatal(value, e)
	}
	return value.(RepositoryPostingResult).ThreadKey
}

// TestBodyCarryCleanupMaintenanceStops は実保守の各耐久停止後に同じ入口で回収を完了する。
func TestBodyCarryCleanupMaintenanceStops(t *testing.T) {
	for _, stage := range []string{"carry_erasure:source", "carry_erasure:rows", "carry_snapshot:switched", "carry_snapshot:old_unlinked"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
			b := r.posting[owner]
			stop := errors.New("maintenance interrupted")
			b.deletionCheckpoint = func(s string) error {
				if s == stage {
					return stop
				}
				return nil
			}
			r.mu.Lock()
			e := r.sweepBodyCarryRetirementsLocked(t.Context())
			r.mu.Unlock()
			if !errors.Is(e, stop) {
				t.Fatal("stop omitted", e)
			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			runCarryMaintenance(t, reopened)
			assertCarrySourceSnapshot(t, filepath.Join(cfg.DataDir, "expiry", owner.String(), fmt.Sprint(key)), owner, key)
			assertCarryRateCount(t, reopened.posting[owner], key, 0)
		})
	}
}
