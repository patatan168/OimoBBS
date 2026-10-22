// 実Repositoryの元延長証明を起動前照合/終端解除へ渡し、途中状態と承認差替えを検証する。
package bootstrap

import (
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// productRequiredExtension は実投稿原本/元予約へ署名済み案件延長を準備する。
func productRequiredExtension(t *testing.T, r *Repository, id domain.ID) disclosure.Case {
	t.Helper()
	c, receipt, _ := productRequiredReservation(t, r, id)
	r.mu.Lock()
	defer r.mu.Unlock()
	c, e := r.evidenceCases.BindRequiredReservation(c.ID, c.Creator, c.ETag(), receipt, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = r.enableRequiredExtensionReaderLocked(); e != nil {
		t.Fatal(e)
	}
	c, e = r.evidenceCases.PrepareRequiredExtension(c.ID, c.Creator, c.ETag(), "required-extend", "原本延長", c.Until+domain.Time(24*time.Hour), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return c
}

// productRequiredRenewal は元所有列で更新し、同じ列から承認証明を取得する。
func productRequiredRenewal(t *testing.T, r *Repository, c disclosure.Case, wrong bool) app.RequiredHoldRenewalReceipt {
	t.Helper()
	b := r.posting[c.Scope.Board]
	a, e := c.RequiredExtensionApproval()
	if e != nil {
		t.Fatal(e)
	}
	if wrong {
		a.Revision++
	}
	value, e := b.worker.Submit(t.Context(), func() (any, error) {
		if _, e := b.requiredHolds.Renew(c.RequiredExtension.Original, a, c.RequiredExtension.Until, b.journals, domain.Time(time.Now().UnixNano())); e != nil {
			return nil, e
		}
		p, found, e := b.requiredHolds.RenewalReceipt(c.ID)
		if e != nil {
			return nil, e
		}
		if !found {
			return nil, store.ErrCorrupt
		}
		return p, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return value.(app.RequiredHoldRenewalReceipt)
}

// inspectProductRequiredExtension は保存済みsite readerと全署名集合を変更せず検査する。
func inspectProductRequiredExtension(t *testing.T, cfg Config, r *Repository) error {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	if site.MinimumReader != 47 {
		t.Fatal("extension reader was not saved before intent", site.MinimumReader)
	}
	return inspectRequiredHoldStorage(cfg, site, r.site.State(), false)
}

func TestRequiredExtensionProductMetadataAndTerminalRecovery(t *testing.T) {
	for _, stage := range []string{"unadvanced_cancel", "renewed_cancel", "released_unreflected", "confirmed_cancel"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, id := requiredHoldStorageFixture(t)
			c := productRequiredExtension(t, r, id)
			originalUntil := c.Until
			var proof app.RequiredHoldRenewalReceipt
			if stage != "unadvanced_cancel" {
				proof = productRequiredRenewal(t, r, c, false)
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			if e := inspectProductRequiredExtension(t, cfg, r); e != nil {
				t.Fatal("pending source inspection", e)
			}
			assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
			r.mu.Lock()
			if stage == "confirmed_cancel" {
				var e error
				c, e = r.evidenceCases.CompleteRequiredExtension(c.ID, c.Creator, c.ETag(), proof, time.Now(), func() error { return nil })
				if e != nil {
					r.mu.Unlock()
					t.Fatal(e)
				}
			}
			c, e := r.evidenceCases.Release(c.ID, c.Creator, c.ETag(), "cancel", "取消", time.Now())
			r.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			b := r.posting[id]
			if stage == "released_unreflected" {
				if _, e = b.worker.Submit(t.Context(), func() (any, error) { return b.requiredHolds.Release(proof.Current, domain.Time(time.Now().UnixNano())) }); e != nil {
					t.Fatal(e)
				}
			}
			if e = inspectProductRequiredExtension(t, cfg, r); e != nil {
				t.Fatal("terminal intermediate inspection", e)
			}
			r.mu.Lock()
			c, e = r.reconcileTerminalRequiredHold(t.Context(), c, b)
			r.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			if c.State != "closed" || c.Required.Released == nil {
				t.Fatal("terminal not fully released")
			}
			if stage != "confirmed_cancel" && c.Until != originalUntil {
				t.Fatal("cancel published new deadline")
			}
			if e = inspectProductRequiredExtension(t, cfg, r); e != nil {
				t.Fatal("terminal completed inspection", e)
			}
			before = requiredStartupFiles(t, cfg.DataDir)
			r.mu.Lock()
			_, e = r.reconcileTerminalRequiredHold(t.Context(), c, b)
			r.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
		})
	}
}

func TestRequiredExtensionProductRejectsWrongSourceApproval(t *testing.T) {
	cfg, r, id := requiredHoldStorageFixture(t)
	c := productRequiredExtension(t, r, id)
	_ = productRequiredRenewal(t, r, c, true)
	before := requiredStartupFiles(t, cfg.DataDir)
	if e := inspectProductRequiredExtension(t, cfg, r); e == nil {
		t.Fatal("wrong source approval accepted")
	}
	assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
}

func TestRequiredExtensionPendingOriginalInspectionAfterOldDeadline(t *testing.T) {
	cfg, r, id := requiredHoldStorageFixture(t)
	c := productRequiredExtension(t, r, id)
	original := c.RequiredExtension.Original
	now := c.Until + 1
	// 新期限への投影は元参照を変更せず、旧期限後にも実原本を要求する。
	if e := inspectRequiredHeldOriginalsWithCases(cfg.DataDir, r.posting[id].key, []app.RequiredHoldReceipt{original}, []disclosure.RequiredCaseInspection{{Current: c}}, now); e != nil {
		t.Fatal(e)
	}
	if original.Binding.Until != c.Until {
		t.Fatal("inspection mutated source")
	}
	path := filepath.Join(cfg.DataDir, "evidence", id.String(), strconv.FormatUint(uint64(original.Postings[0].Proposal.Day), 10))
	key := append([]byte(nil), r.posting[id].key...)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if e := os.RemoveAll(path); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	if e := inspectRequiredHeldOriginalsWithCases(cfg.DataDir, key, []app.RequiredHoldReceipt{original}, []disclosure.RequiredCaseInspection{{Current: c}}, now); e == nil {
		t.Fatal("pending approved originals missing accepted")
	}
	assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
}
