// 実投稿Journal/必須予約/保全copyの歴史的時刻fixtureから、製品の180日回収と元巻戻し拒否を検査する。
package bootstrap

import (
	"context"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// historicalRequiredRetirementFixture は板所有者の既存clockを使い、実署名原本/予約/copy/解除を過去時刻で保存する。
func historicalRequiredRetirementFixture(t *testing.T) (Config, *Repository, disclosure.Case, map[string][]byte) {
	t.Helper()
	cfg, r, info := postingRepositoryFixture(t)
	board := info.ID
	b := r.posting[board]
	if b.expiryCancel != nil {
		b.expiryCancel()
		<-b.expiryDone
	}
	frame, at := expiredRequiredFrame(t)
	_, e := b.worker.Submit(t.Context(), func() (any, error) {
		b.clock = func() time.Time { return time.Unix(0, int64(at)) }
		return nil, nil
	})
	if e != nil {
		t.Fatal("set historical clock", e)
	}
	if e = r.ensureRequiredHoldStorage(t.Context(), board); e != nil {
		t.Fatal("activate historical holds", e)
	}
	value, e := b.worker.Submit(t.Context(), func() (any, error) {
		result := b.post(0, frame, []byte(`{"fixture":true}`))
		if result.Status != store.Durable {
			return nil, store.ErrCorrupt
		}
		return app.AcceptedRecords(mapJournalValues(b))
	})
	if e != nil {
		t.Fatal("post historical original", e)
	}
	rows := value.([]app.AcceptedEvidence)
	if len(rows) != 1 {
		t.Fatal("missing actual accepted original", len(rows))
	}
	var c disclosure.Case
	var active map[string][]byte
	func() {
		r.optionalHoldLifecycleMu.Lock()
		defer r.optionalHoldLifecycleMu.Unlock()
		r.mu.Lock()
		defer r.mu.Unlock()
		var receipt app.RequiredHoldReceipt
		c, receipt = prepareHistoricalRequiredCase(t, r, b, rows, at)
		active = requiredStartupFiles(t, requiredHoldStoragePath(cfg.DataDir, board))
		c = closeHistoricalRequiredCase(t, r, b, c, receipt, at)
	}()
	_, e = b.worker.Submit(t.Context(), func() (any, error) { b.clock = time.Now; return nil, nil })
	if e != nil {
		t.Fatal("restore owner clock", e)
	}
	return cfg, r, c, active
}

// mapJournalValues は板所有列内で現在のJournal集合を検査へ渡す。
func mapJournalValues(b *postingBoard) []*evidence.Journal {
	result := []*evidence.Journal{}
	for _, j := range b.journals {
		result = append(result, j)
	}
	return result
}

// prepareHistoricalRequiredCase は署名済み受理原本から予約をSyncし、元再照合付きで保全copyを完成する。
func prepareHistoricalRequiredCase(t *testing.T, r *Repository, b *postingBoard, rows []app.AcceptedEvidence, at domain.Time) (disclosure.Case, app.RequiredHoldReceipt) {
	t.Helper()
	now := time.Unix(0, int64(at)).Add(time.Second)
	c, e := r.evidenceCases.Create(disclosure.Case{Number: "historical-required", Reason: "fixture", Scope: disclosure.Scope{Board: b.owner, From: at - 1, To: at + 1}, Until: domain.Time(now.Add(24 * time.Hour).UnixNano())}, domain.NewID(), `"evidence:new"`, "registry-create", now)
	if e != nil {
		t.Fatal("create historical case", e)
	}
	c, e = r.evidenceCases.PrepareHold(c.ID, c.Creator, c.ETag(), "required-hold", "fixture", rows, now)
	if e != nil {
		t.Fatal("prepare historical hold", e)
	}
	binding, e := r.evidenceCases.RequiredReservationBinding(c, now)
	if e != nil {
		t.Fatal("derive historical binding", e)
	}
	value, e := b.worker.Submit(t.Context(), func() (any, error) {
		return b.requiredHolds.Reserve(binding, rows, b.journals, domain.Time(now.UnixNano()))
	})
	if e != nil {
		t.Fatal("reserve historical source", e)
	}
	receipt := value.(app.RequiredHoldReceipt)
	c, e = r.evidenceCases.BindRequiredReservation(c.ID, c.Creator, c.ETag(), receipt, now)
	if e != nil {
		t.Fatal("bind historical source", e)
	}
	c, e = r.evidenceCases.ResumeRequiredReserved(c.ID, c.Creator, c.ETag(), rows, receipt, now, func() error {
		_, e := b.worker.Submit(t.Context(), func() (any, error) { return b.requiredHolds.Fetch(receipt, b.journals, domain.Time(now.UnixNano())) })
		return e
	})
	if e != nil {
		t.Fatal("copy historical original", e)
	}
	return c, receipt
}

// closeHistoricalRequiredCase はcopyの物理削除後に元をCAS解除し、実解除署名の参照を案件へ保存する。
func closeHistoricalRequiredCase(t *testing.T, r *Repository, b *postingBoard, c disclosure.Case, receipt app.RequiredHoldReceipt, at domain.Time) disclosure.Case {
	t.Helper()
	now := time.Unix(0, int64(at)).Add(2 * time.Second)
	c, e := r.evidenceCases.Release(c.ID, c.Creator, c.ETag(), "historical-close", "fixture", now)
	if e != nil {
		t.Fatal("close historical case", e)
	}
	value, e := b.worker.Submit(t.Context(), func() (any, error) { return b.requiredHolds.Release(receipt, domain.Time(now.UnixNano())) })
	if e != nil {
		t.Fatal("release historical source", e)
	}
	c, e = r.evidenceCases.RecordRequiredRelease(c.ID, c.Creator, c.ETag(), value.(app.RequiredHoldReceipt), now)
	if e != nil {
		t.Fatal("record historical release", e)
	}
	return c
}

func TestCaseRetirementRequiredSourceMaintenanceAndProductReopen(t *testing.T) {
	cfg, r, c, _ := historicalRequiredRetirementFixture(t)
	before := requiredStartupFiles(t, requiredHoldStoragePath(cfg.DataDir, c.Scope.Board))
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	e := r.reconcileRequiredRetentionLocked(context.Background())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(filepath.Join(cfg.DataDir, "cases", c.ID.String())); !os.IsNotExist(e) {
		t.Fatal("case remained", e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, requiredHoldStoragePath(cfg.DataDir, c.Scope.Board))) {
		t.Fatal("case reclamation modified source history")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = checkLockedPosting(cfg, false, true); e != nil {
		t.Fatal("released source rejected after retirement", e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	checkRetiredCaseCreationRefused(t, reopened, c)
	checkRetirementSlotReusable(t, reopened, c)
}

func TestCaseRetirementRequiredSourcePartialStartupAndLossRefusal(t *testing.T) {
	for _, damage := range []string{"valid", "missing", "rollback"} {
		t.Run(damage, func(t *testing.T) {
			cfg, r, c, active := historicalRequiredRetirementFixture(t)
			registerRequiredRetirementForTest(t, r, c)
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(cfg.DataDir, "cases", c.ID.String())
			if e := os.Remove(filepath.Join(path, "control", "control.current")); e != nil {
				t.Fatal(e)
			}
			damageRetiredRequiredSource(t, cfg, c, active, damage)
			before := requiredStartupFiles(t, cfg.DataDir)
			opened, e := OpenPostingRepository(cfg, postingCaptureFixture)
			if damage == "valid" {
				if e != nil {
					t.Fatal("actual release did not allow resumption", e)
				}
				defer opened.Close()
				if _, e = os.Lstat(path); !os.IsNotExist(e) {
					t.Fatal("case remained", e)
				}
				checkRetiredCaseCreationRefused(t, opened, c)
			} else {
				if opened != nil {
					_ = opened.Close()
				}
				if e == nil {
					t.Fatal("source loss or rollback accepted")
				}
				if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
					t.Fatal("source refusal changed remainder")
				}
			}
		})
	}
}

// registerRequiredRetirementForTest は共通排他下で現在の実解除と候補を再照合して先行登録する。
func registerRequiredRetirementForTest(t *testing.T, r *Repository, c disclosure.Case) {
	t.Helper()
	receipt := requiredSourceReceipt(t, r, c)
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	plans, e := r.evidenceCases.PlanCaseRetirement(time.Now())
	if e != nil || len(plans) != 1 {
		t.Fatal("case not eligible", plans, e)
	}
	if _, e = r.registerCaseRetirementLocked(t.Context(), plans[0], []app.RequiredHoldReceipt{receipt}, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
}

// damageRetiredRequiredSource は停止済み試験領域の元を欠落または正しい旧active署名へ巻き戻す。
func damageRetiredRequiredSource(t *testing.T, cfg Config, c disclosure.Case, active map[string][]byte, damage string) {
	t.Helper()
	if damage == "missing" {
		if e := os.RemoveAll(requiredHoldStoragePath(cfg.DataDir, c.Scope.Board)); e != nil {
			t.Fatal(e)
		}
	}
	if damage == "rollback" {
		for name, body := range active {
			if e := os.WriteFile(name, body, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
}
