// 実HTTP元/copy/解除から180日後の回収を引数時計で検査し、現実時計への巻戻し起動を拒否する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestCaseRetirementActualOptionalReleaseReclaimsAtBoundaryAndRefusesClockRollback(t *testing.T) {
	cfg, r, c, entries, _ := optionalHeldCaseProductFixture(t)
	func() {
		r.optionalHoldLifecycleMu.Lock()
		defer r.optionalHoldLifecycleMu.Unlock()
		r.mu.Lock()
		defer r.mu.Unlock()
		c = completeOptionalRetirementCopy(t, r, c, entries)
		c = closeOptionalRetirementCase(t, r, c)
	}()
	before := requiredStartupFiles(t, filepath.Join(cfg.DataDir, "reports", "http"))
	future := time.Unix(0, int64(c.Closed)).Add(180*24*time.Hour + time.Second)
	reclaimActualOptionalCaseAt(t, r, future)
	if _, e := os.Lstat(filepath.Join(cfg.DataDir, "cases", c.ID.String())); !os.IsNotExist(e) {
		t.Fatal("HTTP case remained", e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, filepath.Join(cfg.DataDir, "reports", "http"))) {
		t.Fatal("retirement modified HTTP source")
	}
	r.mu.Lock()
	_, creationErr := r.evidenceCases.Create(disclosure.Case{Number: c.Number, Reason: c.Reason, Scope: c.Scope}, c.Creator, `"evidence:new"`, "holdproof-case", time.Now())
	r.mu.Unlock()
	if creationErr != disclosure.ErrExpired {
		t.Fatal("retired HTTP case request recreated", creationErr)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	all := requiredStartupFiles(t, cfg.DataDir)
	opened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if opened != nil {
		_ = opened.Close()
	}
	if !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("clock rollback after signed retirement accepted", e)
	}
	if !reflect.DeepEqual(all, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("clock refusal changed source or case state")
	}
}

// completeOptionalRetirementCopy は現在元の再照合付きで実HTTPcopyを完成し、署名付き実体を読む。
func completeOptionalRetirementCopy(t *testing.T, r *Repository, c disclosure.Case, entries []evidence.Entry) disclosure.Case {
	t.Helper()
	ref := *c.HTTP.Reservation
	c, e := r.evidenceCases.ResumeHTTPReserved(c.ID, c.Creator, c.ETag(), entries, ref, time.Now(), func() error {
		return r.awaitOptionalHoldOwner(func() error {
			current, e := r.optionalStore.CheckOptionalHoldReceipt(ref)
			if e != nil {
				return e
			}
			if current.State != "active" || current.SHA != ref.SHA {
				return store.ErrIncomplete
			}
			return nil
		})
	})
	if e != nil {
		t.Fatal(e)
	}
	copy, e := r.evidenceCases.HTTPRecords(c, time.Now())
	if e != nil || len(copy) != len(entries) || len(copy) == 0 {
		t.Fatal("actual HTTP copy not completed", len(copy), e)
	}
	return c
}

// reclaimActualOptionalCaseAt は実元の署名読取り検査後、指定時計の既存回収入口を実行する。
func reclaimActualOptionalCaseAt(t *testing.T, r *Repository, now time.Time) {
	t.Helper()
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	before, e := r.evidenceCases.PlanCaseRetirement(now.Add(-2 * time.Second))
	if e != nil || len(before) != 0 {
		t.Fatal("HTTP case became eligible before 180 days", before, e)
	}
	plans, e := r.evidenceCases.PlanCaseRetirement(now)
	if e != nil || len(plans) != 1 {
		t.Fatal("actual HTTP case not eligible", plans, e)
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	seed, key, e := readRetirementKey(r.cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	defer clear(key)
	required, optional, e := retirementStartupSources(r.cfg, site, r.site.State(), key)
	if e != nil {
		t.Fatal("actual current source inspection failed", e)
	}
	if e = r.saveAndReclaimCaseLocked(t.Context(), plans[0], required.Receipts, optional, site.MinimumReader, now); e != nil {
		t.Fatal(e)
	}
}

// closeOptionalRetirementCase は実保全copyを取消/削除し、現在HTTP元の実解除を案件へ署名保存する。
func closeOptionalRetirementCase(t *testing.T, r *Repository, c disclosure.Case) disclosure.Case {
	t.Helper()
	c, e := r.evidenceCases.Release(c.ID, c.Creator, c.ETag(), "optional-retirement-close", "fixture", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	c, e = r.reconcileTerminalOptionalHold(context.Background(), c, r.optionalStore)
	if e != nil {
		t.Fatal(e)
	}
	if c.HTTP == nil || c.HTTP.Released == nil {
		t.Fatal("actual HTTP release missing")
	}
	if e = r.optionalStore.CheckOptionalHoldRelease(*c.HTTP.Released); e != nil {
		t.Fatal(e)
	}
	return c
}
