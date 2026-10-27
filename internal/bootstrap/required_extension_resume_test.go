// 実製品reader47で起動/周期の延長再開、確認待ち中取消、context/現在認可の検査を確認する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/postcapture"
	"testing"
	"time"
)

func TestRequiredExtensionAutomaticResumeAndReopen(t *testing.T) {
	for _, stage := range []string{"intent", "source_updated", "confirmed"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, id := requiredHoldStorageFixture(t)
			c := productRequiredExtension(t, r, id)
			until := c.RequiredExtension.Until
			if stage != "intent" {
				p := productRequiredRenewal(t, r, c, false)
				if stage == "confirmed" {
					r.mu.Lock()
					var e error
					c, e = r.evidenceCases.CompleteRequiredExtension(c.ID, c.Creator, c.ETag(), p, time.Now(), func() error { return nil })
					r.mu.Unlock()
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			if _, e := checkLockedPosting(cfg, false, true); e != nil {
				t.Fatal("reader47 read-only check", e)
			}
			assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
			r2, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal("automatic resume", e)
			}
			defer r2.Close()
			r2.mu.Lock()
			c, e = r2.evidenceCases.Get(c.ID)
			r2.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			if c.RequiredExtension.State != "complete" || c.Until != until || c.Required.Reservation.Binding.Until != until || c.State != "preparing" {
				t.Fatal("restart failed to confirm", c.State)
			}
			before = requiredStartupFiles(t, cfg.DataDir)
			r2.optionalHoldLifecycleMu.Lock()
			r2.mu.Lock()
			e = r2.reconcileRequiredRetentionLocked(t.Context())
			r2.mu.Unlock()
			r2.optionalHoldLifecycleMu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
			if e = r2.Close(); e != nil {
				t.Fatal(e)
			}
			before = requiredStartupFiles(t, cfg.DataDir)
			r3, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			defer r3.Close()
			assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
		})
	}
}

func TestRequiredExtensionResumeCancellationAtSourceSync(t *testing.T) {
	cfg, r, id := requiredHoldStorageFixture(t)
	c := productRequiredExtension(t, r, id)
	old := c.Until
	r.requiredExtensionAfterRenew = func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		_, e := r.evidenceCases.Release(c.ID, c.Creator, c.ETag(), "cancel-sync", "取消", time.Now())
		if e != nil {
			t.Error(e)
		}
	}
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	_, e := r.renewPendingRequiredExtension(t.Context(), c, r.posting[id], nil)
	r.requiredExtensionAfterRenew = nil
	current, getErr := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if !errors.Is(e, disclosure.ErrRevision) || getErr != nil {
		t.Fatal(e, getErr)
	}
	if current.State != "closed" || current.Until != old || current.Required.Released == nil || current.RequiredExtension.State != "pending" {
		t.Fatal("cancel resurrected or source not released")
	}
	if e = inspectProductRequiredExtension(t, cfg, r); e != nil {
		t.Fatal(e)
	}
}

func TestRequiredExtensionResumeRechecksAuthorizationAndContext(t *testing.T) {
	for _, kind := range []string{"authorization", "context"} {
		t.Run(kind, func(t *testing.T) {
			cfg, r, id := requiredHoldStorageFixture(t)
			c := productRequiredExtension(t, r, id)
			old := c.Until
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			denied := errors.New("current authorization lost")
			allowed := true
			r.requiredExtensionAfterRenew = func() {
				if kind == "context" {
					cancel()
				} else {
					allowed = false
				}
			}
			recheck := func() error {
				if !allowed {
					return denied
				}
				return nil
			}
			r.optionalHoldLifecycleMu.Lock()
			r.mu.Lock()
			_, e := r.renewPendingRequiredExtension(ctx, c, r.posting[id], recheck)
			r.requiredExtensionAfterRenew = nil
			current, getErr := r.evidenceCases.Get(c.ID)
			r.mu.Unlock()
			r.optionalHoldLifecycleMu.Unlock()
			if getErr != nil || e == nil {
				t.Fatal(e, getErr)
			}
			if kind == "context" && !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			if kind == "authorization" && !errors.Is(e, denied) {
				t.Fatal(e)
			}
			if current.Until != old || current.RequiredExtension.State != "pending" || current.Required.Released != nil {
				t.Fatal("unconfirmed deadline published or legitimate source released")
			}
			if e = inspectProductRequiredExtension(t, cfg, r); e != nil {
				t.Fatal(e)
			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal("signed intent not resumed", e)
			}
			defer reopened.Close()
			reopened.mu.Lock()
			current, e = reopened.evidenceCases.Get(c.ID)
			reopened.mu.Unlock()
			if e != nil || current.RequiredExtension.State != "complete" {
				t.Fatal(e)
			}
		})
	}
}
