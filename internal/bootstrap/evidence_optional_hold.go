// 案件の先行intentと元HTTP予約を、所有者待ち中の案件mutex解放・現在認可/CAS再検査で接続する。
package bootstrap

import (
	"context"
	"errors"
	"slices"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// awaitOptionalHoldOwner は案件排他を解放して元所有者を待ち、error/停止時も排他を取り直す。
func (r *Repository) awaitOptionalHoldOwner(fn func() error) error {
	r.mu.Unlock()
	defer r.mu.Lock()
	return fn()
}

// recheckOptionalHold は元所有者待ち後の現在権限・再認証・案件版・期限と同じ所有者を照合する。
func (r *Repository) recheckOptionalHold(session adminauth.Session, c disclosure.Case, source *evidence.OptionalStore) error {
	if e := r.available(); e != nil {
		return e
	}
	if r.optionalStore != source {
		return store.ErrIncomplete
	}
	if e := r.authorizeEvidence(session, "evidence.manage", c.Scope.Board, true); e != nil {
		return e
	}
	_, e := r.evidenceCases.AuthorizeState(c.ID, c.ETag(), time.Now())
	return e
}

// holdOptionalHTTP は案件mutexを保持して入り、戻る時も保持する。元所有者待ちでは解放する。
func (r *Repository) holdOptionalHTTP(ctx context.Context, session adminauth.Session, c disclosure.Case, etag, key, purpose string, unboundMode ...bool) (disclosure.Case, error) {
	unbound := slices.Contains(unboundMode, true)
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	if e := r.checkOptionalHTTPRequest(ctx, session, c); e != nil {
		return c, e
	}
	source := r.optionalStore
	site := siteID(r.site.State())
	if source == nil {
		return c, &adminFailure{status: 409, code: "OPTIONAL_HTTP_NOT_ENABLED"}
	}
	if c.HTTP != nil && c.HTTP.State == "active" {
		completed, e := r.prepareHTTPHoldMode(c, session, etag, key, purpose, site, nil, unbound)
		if e != nil {
			return completed, e
		}
		return r.releaseCompletedOptionalHold(ctx, session, completed, source)
	}
	c, entries, reserve, e := r.prepareOptionalHTTPIntent(ctx, session, c, source, etag, key, purpose, unbound)
	if e != nil || !reserve {
		return c, e
	}
	c, entries, receipt, e := r.bindOptionalHTTPSource(ctx, session, c, source, entries)
	if e != nil {
		return c, e
	}
	c, e = r.resumeOptionalHTTPSource(ctx, session, c, source, entries, receipt)
	if e != nil {
		return c, e
	}
	return r.releaseCompletedOptionalHold(ctx, session, c, source)
}

// prepareOptionalHTTPIntent は元集合の取得後に現在認可/CASを検査し、固定intentを署名する。
// 元集合の不足を保存形式の差として補完しない。
func (r *Repository) prepareOptionalHTTPIntent(ctx context.Context, session adminauth.Session, c disclosure.Case, source *evidence.OptionalStore, etag, key, purpose string, unbound bool) (disclosure.Case, []evidence.Entry, bool, error) {
	site := siteID(r.site.State())
	scope, e := r.optionalHTTPHoldScopeMode(c, time.Now(), unbound)
	if e != nil {
		return c, nil, false, e
	}
	var entries []evidence.Entry
	var known evidence.OptionalHoldReceipt
	e = r.awaitOptionalHoldOwner(func() error {
		var err error
		entries, known, err = optionalHTTPIntentEntries(ctx, c, source, scope, unbound)
		return err
	})
	if errors.Is(e, evidence.ErrOptionalQueryLimit) {
		return c, nil, false, disclosure.ErrLimit
	}
	if e != nil {
		return c, nil, false, e
	}
	if e = r.recheckOptionalHold(session, c, source); e != nil {
		return c, nil, false, e
	}
	if e = ctx.Err(); e != nil {
		return c, nil, false, e
	}
	if missingUnboundHTTPSelection(c, entries, unbound) {
		return c, nil, false, disclosure.ErrExpired
	}
	c, e = r.prepareHTTPHoldMode(c, session, etag, key, purpose, site, entries, unbound)
	if e != nil {
		return c, nil, false, e
	}
	return r.finishOptionalHTTPIntent(c, session, etag, key, purpose, site, entries, known, unbound)
}

// adoptOptionalHTTPReference は元署名で直後と確認した未反映参照を、次の元更新より先に案件へ保存する。
func (r *Repository) adoptOptionalHTTPReference(session adminauth.Session, c disclosure.Case, known evidence.OptionalHoldReceipt) (disclosure.Case, error) {
	if c.HTTP.Reservation == nil || known.Sequence <= c.HTTP.Reservation.Sequence {
		return c, nil
	}
	return r.evidenceCases.BindHTTPReservation(c.ID, session.Admin, c.ETag(), known, time.Now())
}

// bindOptionalHTTPSource は先行intentの元予約Syncを案件排他外で行い、再認可後に耐久参照を署名する。
func (r *Repository) bindOptionalHTTPSource(ctx context.Context, session adminauth.Session, c disclosure.Case, source *evidence.OptionalStore, entries []evidence.Entry) (disclosure.Case, []evidence.Entry, evidence.OptionalHoldReceipt, error) {
	binding, e := r.evidenceCases.HTTPReservationBinding(c, time.Now())
	if e != nil {
		return c, nil, evidence.OptionalHoldReceipt{}, e
	}
	var receipt evidence.OptionalHoldReceipt
	beforeReserve := r.optionalHoldBeforeReserve
	afterReserve := r.optionalHoldAfterReserve
	e = r.awaitOptionalHoldOwner(func() error {
		if beforeReserve != nil {
			beforeReserve()
		}
		if err := source.ReloadOptionalHolds(); err != nil {
			return err
		}
		if err := source.ReserveOptionalHold(ctx, binding, entries, time.Now()); err != nil {
			if errors.Is(err, evidence.ErrOptionalQueryLimit) {
				return disclosure.ErrLimit
			}
			return err
		}
		if afterReserve != nil {
			afterReserve()
		}
		var found bool
		var err error
		receipt, found, err = source.OptionalHoldReceipt(c.ID)
		if err != nil {
			return err
		}
		if !found || receipt.State != "active" {
			return store.ErrIncomplete
		}
		entries, err = source.QueryOptionalHold(ctx, c.ID, time.Now())
		return err
	})
	if e != nil {
		return c, nil, evidence.OptionalHoldReceipt{}, errors.Join(e, r.cleanupCancelledOptionalHold(c, source))
	}
	if e = r.recheckOptionalHold(session, c, source); e != nil {
		return c, nil, evidence.OptionalHoldReceipt{}, errors.Join(e, r.cleanupCancelledOptionalHold(c, source))
	}
	if e = ctx.Err(); e != nil {
		return c, nil, evidence.OptionalHoldReceipt{}, e
	}
	c, e = r.evidenceCases.BindHTTPReservation(c.ID, session.Admin, c.ETag(), receipt, time.Now())
	return c, entries, receipt, e
}

// resumeOptionalHTTPSource は各copyとcomplete前に元所有者を排他外で再照合し、最新の認可/CASを検査する。
func (r *Repository) resumeOptionalHTTPSource(ctx context.Context, session adminauth.Session, c disclosure.Case, source *evidence.OptionalStore, entries []evidence.Entry, receipt evidence.OptionalHoldReceipt) (disclosure.Case, error) {
	bound := c
	check := func() error {
		err := r.awaitOptionalHoldOwner(func() error {
			if e := ctx.Err(); e != nil {
				return e
			}
			current, found, e := source.OptionalHoldReceipt(bound.ID)
			if e != nil {
				return e
			}
			if !found || current.State != "active" || current.Site != receipt.Site || current.Sequence != receipt.Sequence || current.SHA != receipt.SHA || current.Binding.Until <= 0 {
				return store.ErrIncomplete
			}
			return nil
		})
		if err != nil {
			return err
		}
		return r.recheckOptionalHold(session, bound, source)
	}
	return r.evidenceCases.ResumeHTTPReserved(c.ID, session.Admin, c.ETag(), entries, receipt, time.Now(), check)
}

// releaseCompletedOptionalHold は署名済みcopy completeの後だけ元予約を解除し、返す前にも現在認可を照合する。
func (r *Repository) releaseCompletedOptionalHold(ctx context.Context, session adminauth.Session, c disclosure.Case, source *evidence.OptionalStore) (disclosure.Case, error) {
	if c.HTTP == nil || c.HTTP.State != "active" || c.HTTP.Reservation == nil {
		return c, nil
	}
	c, e := r.reconcileTerminalOptionalHold(ctx, c, source)
	if e != nil {
		return c, e
	}
	return c, r.recheckOptionalHold(session, c, source)
}

// releaseCancelledOptionalHold は案件取消の署名確定後、元予約も同期解除する。不存在は未予約として扱う。
// 案件mutexを保持して入り、元所有者を待つ間は解放し、戻る前に現在認可を検査する。
func (r *Repository) releaseCancelledOptionalHold(ctx context.Context, session adminauth.Session, c disclosure.Case) (disclosure.Case, error) {
	source := r.optionalStore
	if source == nil {
		return c, nil
	}
	c, e := r.reconcileTerminalOptionalHold(ctx, c, source)
	if e != nil {
		return c, e
	}
	return c, r.authorizeEvidence(session, "evidence.manage", c.Scope.Board, true)
}

// cleanupCancelledOptionalHold は元Sync待ち中に取消が先行した場合、署名済み取消を根拠に遅れて作った予約を解除する。
// 要求取消後も既に署名した案件取消の後処理を完了し、現権限の喪失だけでは合法保全を解除しない。
func (r *Repository) cleanupCancelledOptionalHold(c disclosure.Case, source *evidence.OptionalStore) error {
	current, e := r.evidenceCases.Get(c.ID)
	if e != nil {
		return e
	}
	if current.State != "closed" && current.State != "releasing" {
		return nil
	}
	_, e = r.reconcileTerminalOptionalHold(context.Background(), current, source)
	return e
}

// prepareHTTPHoldMode は入口で明示した種別を固定intentと再送照合へ渡す。
func (r *Repository) prepareHTTPHoldMode(c disclosure.Case, session adminauth.Session, etag, key, purpose string, site domain.ID, entries []evidence.Entry, unbound bool) (disclosure.Case, error) {
	if unbound {
		return r.evidenceCases.PrepareUnboundHTTPHold(c.ID, session.Admin, etag, key, purpose, site, entries, time.Now())
	}
	return r.evidenceCases.PrepareHTTPHold(c.ID, session.Admin, etag, key, purpose, site, entries, time.Now())
}

// optionalHTTPIntentEntries は元所有者で予約の有無を読み、固定予約か期限内原本を取得する。
func optionalHTTPIntentEntries(ctx context.Context, c disclosure.Case, source *evidence.OptionalStore, scope evidence.OptionalQueryScope, unbound bool) ([]evidence.Entry, evidence.OptionalHoldReceipt, error) {
	if e := source.ReloadOptionalHolds(); e != nil {
		return nil, evidence.OptionalHoldReceipt{}, e
	}
	known, found, e := source.OptionalHoldReceipt(c.ID)
	if e != nil {
		return nil, known, e
	}
	if found {
		if c.HTTP == nil || known.State != "active" {
			return nil, known, store.ErrIncomplete
		}
		if c.HTTP.Reservation != nil {
			known, e = source.CheckOptionalHoldReceipt(*c.HTTP.Reservation)
			if e != nil {
				return nil, known, e
			}
		}
		rows, err := source.QueryOptionalHold(ctx, c.ID, time.Now())
		return rows, known, err
	}
	rows, e := optionalHTTPIntentOriginals(ctx, c, source, scope, unbound)
	return rows, known, e
}

// optionalHTTPIntentOriginals は予約未作成時だけ通常期限の固定scopeを選ぶ。
func optionalHTTPIntentOriginals(ctx context.Context, c disclosure.Case, source *evidence.OptionalStore, scope evidence.OptionalQueryScope, unbound bool) ([]evidence.Entry, error) {
	if c.HTTP != nil && c.HTTP.Reservation != nil {
		return nil, store.ErrCorrupt
	}
	if !unbound && len(scope.Operations) == 0 {
		return nil, nil
	}
	if c.HTTP != nil && len(scope.Records) == 0 {
		return nil, nil
	}
	var rows []evidence.Entry
	var e error
	if unbound {
		rows, e = source.QueryUnboundSigned(ctx, scope, time.Now())
	} else {
		rows, e = source.QuerySigned(ctx, scope, time.Now())
	}
	if errors.Is(e, evidence.ErrOptionalQueryLimit) {
		return nil, disclosure.ErrLimit
	}
	return rows, e
}

// missingUnboundHTTPSelection は初回の明示ID欠落を部分成功にしない。
func missingUnboundHTTPSelection(c disclosure.Case, entries []evidence.Entry, unbound bool) bool {
	return unbound && c.HTTP == nil && len(c.Scope.Records) > 0 && len(entries) != len(c.Scope.Records)
}

// finishOptionalHTTPIntent は空集合だけを元予約なしで完了し、他は既存予約へ進める。
func (r *Repository) finishOptionalHTTPIntent(c disclosure.Case, session adminauth.Session, etag, key, purpose string, site domain.ID, entries []evidence.Entry, known evidence.OptionalHoldReceipt, unbound bool) (disclosure.Case, []evidence.Entry, bool, error) {
	if len(c.HTTP.Items) == 0 {
		var completed disclosure.Case
		var err error
		if unbound {
			completed, err = r.evidenceCases.HoldUnboundHTTP(c.ID, session.Admin, etag, key, purpose, site, entries, time.Now())
		} else {
			completed, err = r.evidenceCases.HoldHTTP(c.ID, session.Admin, etag, key, purpose, site, entries, time.Now())
		}
		return completed, nil, false, err
	}
	c, e := r.adoptOptionalHTTPReference(session, c, known)
	return c, entries, true, e
}

// checkOptionalHTTPRequest は所有者排他待ち後に要求と現在の担当/再認証を確認する。
func (r *Repository) checkOptionalHTTPRequest(ctx context.Context, session adminauth.Session, c disclosure.Case) error {
	if e := r.available(); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return r.authorizeEvidence(session, "evidence.manage", c.Scope.Board, true)
}
