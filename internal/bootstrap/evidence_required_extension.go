// 先行署名済み必須延長を元所有列で再開し、待ち後の認可/CASを確認して案件期限を確定する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"time"
)

// enableRequiredExtensionReaderLocked は必須延長intentより先にsite最低reader47を耐久保存する。
func (r *Repository) enableRequiredExtensionReaderLocked() error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if site.MinimumReader >= 47 {
		return nil
	}
	site.MinimumReader = 47
	if e := appendControl(r.site, "required_original_extension_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
		r.stopped = true
		return e
	}
	return nil
}

// requireRequiredExtensionReader は更新前に先行reader保存を確認し、不完全な有効化で元を更新しない。
func (r *Repository) requireRequiredExtensionReader() error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if site.MinimumReader < 47 {
		return store.ErrIncomplete
	}
	return nil
}

// renewPendingRequiredExtension はlifecycle/案件排他下で入り、元待ち中だけ案件排他を解放する。
// recheckは現在認可。起動/周期は新要求を承認せず、署名済みintentのmetadataだけを再開する。
func (r *Repository) renewPendingRequiredExtension(ctx context.Context, c disclosure.Case, b *postingBoard, recheck func() error) (out disclosure.Case, err error) {
	if e := r.requiredExtensionResumeReady(ctx, c, b, recheck); e != nil {
		return c, e
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.cleanupCancelledRequiredHold(c, b))
		}
	}()
	release, e := r.reservePrivateLossBytes(1 << 20)
	if e != nil {
		return c, e
	}
	defer release()
	var proof app.RequiredHoldRenewalReceipt
	after := r.requiredExtensionAfterRenew
	e = r.awaitRequiredHoldOwner(ctx, b, func() error { var e error; proof, e = renewRequiredExtensionSource(b, c); return e })
	if e != nil {
		return c, e
	}
	if after != nil {
		r.mu.Unlock()
		after()
		r.mu.Lock()
	}
	if e = r.recheckPendingRequiredExtension(ctx, c, b, recheck); e != nil {
		return c, e
	}
	check := func() error { return r.checkRequiredExtensionSource(ctx, c, b, proof, recheck) }
	return r.evidenceCases.CompleteRequiredExtension(c.ID, c.RequiredExtension.Actor, c.ETag(), proof, time.Now(), check)
}

// requiredExtensionResumeReady は先行reader/現在案件/認可を元更新前に検査する。
func (r *Repository) requiredExtensionResumeReady(ctx context.Context, c disclosure.Case, b *postingBoard, recheck func() error) error {
	if b == nil || b.requiredHolds == nil || c.RequiredExtension == nil || c.RequiredExtension.State != "pending" {
		return store.ErrIncomplete
	}
	if e := r.requireRequiredExtensionReader(); e != nil {
		return e
	}
	return r.recheckPendingRequiredExtension(ctx, c, b, recheck)
}

// renewRequiredExtensionSource は元所有列で原本を再検査し、同じ承認の直後再送を元証明へ束縛する。
func renewRequiredExtensionSource(b *postingBoard, c disclosure.Case) (app.RequiredHoldRenewalReceipt, error) {
	a, e := c.RequiredExtensionApproval()
	if e != nil {
		return app.RequiredHoldRenewalReceipt{}, e
	}
	if _, e = b.requiredHolds.Renew(c.RequiredExtension.Original, a, c.RequiredExtension.Until, b.journals, domain.Time(time.Now().UnixNano())); e != nil {
		return app.RequiredHoldRenewalReceipt{}, e
	}
	p, found, e := b.requiredHolds.RenewalReceipt(c.ID)
	if e != nil {
		return p, e
	}
	if !found {
		return p, store.ErrCorrupt
	}
	return p, nil
}

// recheckPendingRequiredExtension は所有者/案件版・新回収期限・現在認可を元待ち後にも検査する。
func (r *Repository) recheckPendingRequiredExtension(ctx context.Context, c disclosure.Case, b *postingBoard, recheck func() error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := r.recheckTerminalRequiredHold(c, b); e != nil {
		return e
	}
	if c.State != "preparing" && c.State != "partial" {
		return disclosure.ErrExpired
	}
	if domain.Time(time.Now().UnixNano()) >= c.RetentionUntil() {
		return disclosure.ErrExpired
	}
	if recheck != nil {
		return recheck()
	}
	return nil
}

// checkRequiredExtensionSource は直前の元証明/現在原本/時計を同じ所有列で確認してから案件認可を確認する。
func (r *Repository) checkRequiredExtensionSource(ctx context.Context, c disclosure.Case, b *postingBoard, p app.RequiredHoldRenewalReceipt, recheck func() error) error {
	e := r.awaitRequiredHoldOwner(ctx, b, func() error { return checkRequiredExtensionOwner(b, c.ID, p) })
	if e != nil {
		return e
	}
	return r.recheckPendingRequiredExtension(ctx, c, b, recheck)
}

// checkRequiredExtensionOwner は元所有列で現在行と承認の完全対応を確認する。
func checkRequiredExtensionOwner(b *postingBoard, id domain.ID, p app.RequiredHoldRenewalReceipt) error {
	current, found, e := readTerminalRequiredSource(b.requiredHolds, id)
	if e != nil {
		return e
	}
	if !found || current.Proof == nil || current.Receipt.State != "active" {
		return store.ErrIncomplete
	}
	if !sameRequiredSourceReceipt(current.Receipt, p.Current) || !sameRequiredSourceReceipt(current.Proof.Original, p.Original) || current.Proof.Approval != p.Approval {
		return store.ErrCorrupt
	}
	_, e = b.requiredHolds.Fetch(current.Receipt, b.journals, domain.Time(time.Now().UnixNano()))
	return e
}

// reconcilePendingRequiredExtensionsLocked は既存署名の延長だけを再開する。lifecycle/案件排他を保持して呼ぶ。
func (r *Repository) reconcilePendingRequiredExtensionsLocked(ctx context.Context) error {
	cases, e := r.evidenceCases.Cases()
	if e != nil {
		return e
	}
	for _, c := range cases {
		if c.RequiredExtension == nil || c.RequiredExtension.State != "pending" || terminalRequiredCase(c) {
			continue
		}
		if _, e = r.renewPendingRequiredExtension(ctx, c, r.posting[c.Scope.Board], nil); e != nil {
			return e
		}
	}
	return nil
}

// reconcileRequiredRetentionLocked は満了回収、延長確認、終端解除を同じ巡回内で進める。
func (r *Repository) reconcileRequiredRetentionLocked(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := r.prepareCaseCompletionTailLocked(time.Now()); e != nil {
		return e
	}
	if e := r.prepareCaseExportCleanupLocked(time.Now()); e != nil {
		return e
	}
	if e := r.evidenceCases.Sweep(time.Now()); e != nil {
		return e
	}
	if e := r.reconcilePendingRequiredExtensionsLocked(ctx); e != nil {
		return e
	}
	if e := r.reconcileTerminalRequiredHoldsLocked(ctx); e != nil {
		return e
	}
	if e := r.sweepRequiredCheckpointLocked(ctx); e != nil {
		return e
	}
	if _, e := r.sweepRequiredOriginalsLocked(ctx); e != nil {
		return e
	}
	if e := r.sweepBodyCarryRetirementsLocked(ctx); e != nil {
		return e
	}
	return r.reclaimCaseRetirementsLocked(ctx)
}
