// 未受理の案件intent・板所有列・既存コピー/解除を共通GC排他へ接続する。
package bootstrap

import (
	"context"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"time"
)

// holdRejectedEvidence は案件mutexを解放して共通GC排他を取得し、元待ち後も現在認可を検査する。
func (r *Repository) holdRejectedEvidence(ctx context.Context, s adminauth.Session, c disclosure.Case, etag, key, purpose string) (disclosure.Case, error) {
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	if e := r.recheckRejectedEvidence(s, c, "evidence.manage", nil); e != nil {
		return c, e
	}
	var rows []app.RejectedEvidence
	var e error
	if c.Rejected == nil {
		rows, e = r.collectRejectedEvidence(ctx, c.Scope)
	}
	if e != nil {
		return c, e
	}
	if e = r.recheckRejectedEvidence(s, c, "evidence.manage", rows); e != nil {
		return c, e
	}
	c, e = r.evidenceCases.PrepareRejectedHold(c.ID, s.Admin, etag, key, purpose, rows, time.Now())
	if e != nil {
		return c, e
	}
	if c.Rejected.State == "active" {
		return c, nil
	}
	rows, e = r.collectRejectedReserved(ctx, c)
	if e != nil {
		return c, e
	}
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		return r.recheckRejectedEvidence(s, c, "evidence.manage", rows)
	}
	return r.evidenceCases.ResumeRejectedHold(c.ID, s.Admin, c.ETag(), rows, time.Now(), check)
}

// collectRejectedReserved は先行署名intentの固定範囲を板所有列へ渡し、本文なしで再取得する。
func (r *Repository) collectRejectedReserved(ctx context.Context, c disclosure.Case) ([]app.RejectedEvidence, error) {
	b := r.posting[c.Scope.Board]
	if b == nil || c.Rejected == nil {
		return nil, store.ErrCorrupt
	}
	var rows []app.RejectedEvidence
	e := r.awaitOptionalHoldOwner(func() error {
		value, e := b.worker.Submit(ctx, func() (any, error) {
			if b.stopped {
				return nil, store.ErrIncomplete
			}
			return app.RejectedReservedRecords(requiredGCJournals(b), c.Rejected.Sources, c.Rejected.Captured, c.RetentionUntil(), domain.Time(time.Now().UnixNano()))
		})
		if e != nil {
			return e
		}
		rows = value.([]app.RejectedEvidence)
		return nil
	})
	return rows, e
}
