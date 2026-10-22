// reader47向け元延長履歴をreader46製品が原本回収より前に非変更で拒否する。
package bootstrap

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"strings"
	"testing"
	"time"
)

func TestRequiredHoldRenewalReaderGateBeforeRecovery(t *testing.T) {
	cfg, r, id := requiredHoldStorageFixture(t)
	c, original, _ := productRequiredReservation(t, r, id)
	b := r.posting[id]
	now := domain.Time(time.Now().UnixNano())
	approval := app.RequiredHoldApproval{Revision: c.Revision + 1, At: now}
	if _, e := b.worker.Submit(t.Context(), func() (any, error) {
		return b.requiredHolds.Renew(original, approval, c.Until+domain.Time(time.Hour), b.journals, now)
	}); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	if _, e := checkLockedPosting(cfg, false, true); e == nil || !strings.Contains(e.Error(), "renewal requires reader47") {
		t.Fatal("read-only check accepted renewal history", e)
	}
	if opened, e := OpenPostingRepository(cfg, postcapture.Validate); e == nil {
		opened.Close()
		t.Fatal("product reader46 opened renewal history")
	} else if !strings.Contains(e.Error(), "renewal requires reader47") {
		t.Fatal("wrong startup rejection", e)
	}
	assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
}
