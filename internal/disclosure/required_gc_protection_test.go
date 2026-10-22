// 実署名案件/元予約/原本回収を通し、未反映の承認と初回intentの両側保護を検証する。
package disclosure

import (
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"testing"
	"time"
)

func requiredGCMetadata(t *testing.T, s *Store) []RequiredCaseInspection {
	t.Helper()
	rows, e := InspectRequiredCaseMetadataVersion(s.root, s.key, 47)
	if e != nil {
		t.Fatal(e)
	}
	return rows
}

// pruneRequiredProtected は同じ受理対応の両側へ実Journal回収前の保護を適用する。
func pruneRequiredProtected(t *testing.T, j *evidence.Journal, g *RequiredGCProtection, board domain.ID, p evidence.RequiredPostingIdentity, at domain.Time, expected int) {
	t.Helper()
	selectPair := func(evidence.Entry) (*evidence.RequiredPostingIdentity, error) {
		held, e := g.PairHeld(board, p, at)
		if e != nil || held {
			return nil, e
		}
		return &p, nil
	}
	// 予約保護はselectPair内で両側まとめて検査済み。
	n, e := j.PruneRequired(at, selectPair, func(domain.ID, domain.Time) (bool, error) { return false, nil }, nil)
	if e != nil || n != expected {
		t.Fatal(n, e)
	}
}

func TestRequiredGCPendingExtensionProtectsExpiredSourceThenCancelAllowsPrune(t *testing.T) {
	s, h, j, c, actor, now, _ := requiredExtensionFixture(t)
	r := c.RequiredExtension.Original
	p := r.Postings[0].Identity
	at := c.Until + 1
	if held, e := h.Held(p.ProposalID, at); e != nil || held {
		t.Fatal("fixture source must be expired", held, e)
	}
	g, e := PrepareRequiredGCProtection(requiredGCMetadata(t, s), []app.RequiredHoldReceipt{r}, nil, at, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	pruneRequiredProtected(t, j, g, r.Binding.Board, p, at, 0)
	c, e = s.Release(c.ID, actor, c.ETag(), "gc-cancel", "取消", time.Unix(0, int64(at)))
	if e != nil {
		t.Fatal(e)
	}
	r, e = h.Release(r, at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), r, time.Unix(0, int64(at))); e != nil {
		t.Fatal(e)
	}
	g, e = PrepareRequiredGCProtection(requiredGCMetadata(t, s), []app.RequiredHoldReceipt{r}, nil, at, at)
	if e != nil {
		t.Fatal(e)
	}
	pruneRequiredProtected(t, j, g, r.Binding.Board, p, at, 2)
}

func TestRequiredGCInitialIntentWithoutSourceProtectsBothOriginals(t *testing.T) {
	s, _, j, _, c, _, r, _, now, _ := requiredReservationPreparedFixture(t)
	at := r.Postings[0].Identity.Committed
	at = domain.Time(domain.SixMonths(time.Unix(0, int64(at))).UnixNano()) + 1
	rows := requiredGCMetadata(t, s)
	if rows[0].Current.Required != nil || len(rows[0].Intent.Items) != 1 {
		t.Fatal("fixture requires durable intent before source binding")
	}
	// 初回元予約前の中断と同じ、案件だけを署名検査した集合。
	g, e := PrepareRequiredGCProtection(rows, nil, nil, at, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	p := r.Postings[0].Identity
	pruneRequiredProtected(t, j, g, c.Scope.Board, p, at, 0)
	if _, e = g.PairHeld(c.Scope.Board, p, at+1); !errors.Is(e, ErrConflict) {
		t.Fatal("stale protection reused", e)
	}
	p.ProposalSHA[0] ^= 1
	if _, e = g.PairHeld(c.Scope.Board, p, at); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("source hash substituted", e)
	}
}

func TestRequiredGCProtectionRejectsIncompleteRenewalAndClockRollback(t *testing.T) {
	s, h, j, c, _, now, day := requiredExtensionFixture(t)
	p := renewRequiredFixture(t, h, j, c, day, now)
	rows := requiredGCMetadata(t, s)
	at := domain.Time(now.UnixNano())
	if _, e := PrepareRequiredGCProtection(rows, []app.RequiredHoldReceipt{p.Current}, nil, at, at); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal(e)
	}
	if _, e := PrepareRequiredGCProtection(rows, []app.RequiredHoldReceipt{p.Current}, []app.RequiredHoldRenewalReceipt{p}, at, at+1); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal(e)
	}
	if _, e := PrepareRequiredGCProtection(rows, nil, nil, at, at); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal(e)
	}
	g, e := PrepareRequiredGCProtection(rows, []app.RequiredHoldReceipt{p.Current}, []app.RequiredHoldRenewalReceipt{p}, at, at)
	if e != nil {
		t.Fatal(e)
	}
	// 元更新後でも案件確認前の両原本は保護する。
	pruneRequiredProtected(t, j, g, c.Scope.Board, p.Current.Postings[0].Identity, at, 0)
}
