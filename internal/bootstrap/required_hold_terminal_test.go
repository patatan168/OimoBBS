// 実Repository起動で取消/完成後の元解除と案件参照未保存を回復し、再巡回で再書込みしない。
package bootstrap

import (
	"bytes"
	"context"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"testing"
	"time"
)

func TestRequiredHoldTerminalStartupRecovery(t *testing.T) {
	for _, stage := range []string{"cancel_before_binding", "cancel_after_source_release", "complete_before_source_release", "complete_after_source_release"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, id := requiredHoldStorageFixture(t)
			c, receipt, records := productRequiredReservation(t, r, id)
			r.mu.Lock()
			var e error
			if stage == "cancel_before_binding" || stage == "cancel_after_source_release" {
				c, e = r.evidenceCases.Release(c.ID, c.Creator, c.ETag(), "terminal-startup-cancel", "取消", time.Now())
			} else {
				c, e = r.evidenceCases.BindRequiredReservation(c.ID, c.Creator, c.ETag(), receipt, time.Now())
				if e == nil {
					c, e = r.evidenceCases.ResumeRequiredReserved(c.ID, c.Creator, c.ETag(), records, receipt, time.Now(), func() error { return nil })
				}
			}
			r.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			if stage == "cancel_after_source_release" || stage == "complete_after_source_release" {
				b := r.posting[id]
				if _, e = b.worker.Submit(t.Context(), func() (any, error) { return b.requiredHolds.Release(receipt, domain.Time(time.Now().UnixNano())) }); e != nil {
					t.Fatal(e)
				}
			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e = checkLockedPosting(cfg, false, true); e != nil {
				t.Fatal("pending terminal check", e)
			}
			reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal("terminal recovery", e)
			}
			defer reopened.Close()
			reopened.mu.Lock()
			current, e := reopened.evidenceCases.Get(c.ID)
			reopened.mu.Unlock()
			if e != nil || current.Required == nil || current.Required.Released == nil {
				t.Fatal("terminal reference missing", current, e)
			}
			latest := requiredSourceReceipt(t, reopened, current)
			if latest.State != "released" || latest.SHA != current.Required.Released.SHA || current.Required.Reservation.SHA != receipt.SHA {
				t.Fatal("wrong release or original reservation", latest)
			}
			if current.State == "active" {
				copies, e := reopened.evidenceCases.Records(current, time.Now())
				if e != nil || len(copies) != len(records) {
					t.Fatal("completed copy changed", e)
				}
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			reopened.mu.Lock()
			e = reopened.reconcileTerminalRequiredHoldsLocked(context.Background())
			reopened.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
		})
	}
}

// assertRequiredStartupFilesEqual は再調停が署名履歴やcopyを変更しないことを比較する。
func assertRequiredStartupFilesEqual(t *testing.T, before, after map[string][]byte) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatal("terminal retry changed file set")
	}
	for name, want := range before {
		if got, found := after[name]; !found || !bytes.Equal(got, want) {
			t.Fatal("terminal retry changed", name)
		}
	}
}
