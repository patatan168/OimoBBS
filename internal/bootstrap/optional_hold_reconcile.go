// コピー完了/署名取消後の元予約を、未保存参照の先行署名と元CAS解除で再調停する。
package bootstrap

import (
	"context"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// reconcileTerminalOptionalHold は案件mutex下で入り、元所有者待ちだけ解放する。
// 未保存直後のactive参照を案件へ先に署名し、元CAS解除の競合は次巡回へ残す。
func (r *Repository) reconcileTerminalOptionalHold(ctx context.Context, c disclosure.Case, source *evidence.OptionalStore) (disclosure.Case, error) {
	current, e := r.evidenceCases.Get(c.ID)
	if e != nil {
		return c, e
	}
	c = current
	if !terminalOptionalCase(c) {
		return c, nil
	}
	receipt, found, e := r.lookupTerminalOptionalHold(c, source)
	if e != nil {
		return c, e
	}
	if e = r.recheckTerminalOptionalHold(c, source); e != nil {
		return c, e
	}
	if !found {
		return c, nil
	}
	if receipt.State == "released" {
		return r.recordTerminalOptionalRelease(c, receipt)
	}
	return r.saveAndReleaseTerminalOptionalHold(ctx, c, source, receipt)
}

// saveAndReleaseTerminalOptionalHold は終端参照の先行署名後にだけ元CAS解除を行う。
func (r *Repository) saveAndReleaseTerminalOptionalHold(ctx context.Context, c disclosure.Case, source *evidence.OptionalStore, receipt evidence.OptionalHoldReceipt) (disclosure.Case, error) {
	// 既存終端のmetadataだけを予約し、最後の投稿枠と他所有者の予約を維持する。
	release, e := r.reservePrivateLossBytes(1 << 20)
	if e != nil {
		return c, e
	}
	defer release()
	if c.State != "closed" && c.State != "releasing" {
		if _, e = r.evidenceCases.HTTPRecords(c, time.Now()); e != nil {
			return c, e
		}
	}
	c, e = r.evidenceCases.ReconcileHTTPReservation(c.ID, c.Creator, c.ETag(), receipt, time.Now())
	if e != nil {
		return c, e
	}
	e = r.awaitOptionalHoldOwner(func() error {
		return source.ReleaseOptionalHoldChecked(ctx, receipt, c.Revision, time.Now())
	})
	if e != nil {
		return c, e
	}
	if e = r.recheckTerminalOptionalHold(c, source); e != nil {
		return c, e
	}
	release()
	return r.confirmTerminalOptionalRelease(c, source)
}

// terminalOptionalCase は署名済み取消/満了、またはHTTPコピー完了だけを後処理対象にする。
func terminalOptionalCase(c disclosure.Case) bool {
	return c.HTTP != nil && (c.State == "closed" || c.State == "releasing" || c.HTTP.State == "active")
}

// recheckTerminalOptionalHold は元待ち後に同じ所有者/案件版を要求し、開示の認可は行わない。
func (r *Repository) recheckTerminalOptionalHold(c disclosure.Case, source *evidence.OptionalStore) error {
	if e := r.available(); e != nil {
		return e
	}
	if r.optionalStore != source {
		return store.ErrIncomplete
	}
	current, e := r.evidenceCases.Get(c.ID)
	if e != nil {
		return e
	}
	if current.ETag() != c.ETag() {
		return disclosure.ErrRevision
	}
	return nil
}

// reconcileTerminalOptionalHoldsLocked は現在の署名終端案件だけを巡回し、解除失敗では原本回収を許可しない。
// 呼出元はr.muを保持する。元待ち中だけ解放し、戻る前に再取得する。
func (r *Repository) reconcileTerminalOptionalHoldsLocked(ctx context.Context) error {
	if r.optionalStore == nil {
		return nil
	}
	cases, e := r.evidenceCases.Cases()
	if e != nil {
		return e
	}
	for _, c := range cases {
		if !terminalOptionalCase(c) {
			continue
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if _, e = r.reconcileTerminalOptionalHold(ctx, c, r.optionalStore); e != nil {
			return e
		}
	}
	return nil
}

// reconcileTerminalOptionalHolds は周期処理から現在所有者を取得し、閉鎖中の新しい後処理を開始しない。
func (r *Repository) reconcileTerminalOptionalHolds(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	return r.reconcileTerminalOptionalHoldsLocked(ctx)
}

// lookupTerminalOptionalHold は元所有者の再読取りと署名参照照合を案件排他の外で行う。
func (r *Repository) lookupTerminalOptionalHold(c disclosure.Case, source *evidence.OptionalStore) (evidence.OptionalHoldReceipt, bool, error) {
	var receipt evidence.OptionalHoldReceipt
	var found bool
	e := r.awaitOptionalHoldOwner(func() error {
		if e := source.ReloadOptionalHolds(); e != nil {
			return e
		}
		var e error
		receipt, found, e = source.OptionalHoldReceipt(c.ID)
		if e != nil {
			return e
		}
		if !found {
			if c.HTTP.Reservation != nil || c.HTTP.Released != nil {
				return store.ErrCorrupt
			}
			return nil
		}
		return checkOptionalHoldCase(c, receipt, source)
	})
	return receipt, found, e
}
