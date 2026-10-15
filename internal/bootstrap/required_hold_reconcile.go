// 完成/取消済み案件の必須元予約を耐久参照回復・CAS解除・案件解除署名の順に調停する。
package bootstrap

import (
	"context"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"time"
)

// recheckTerminalRequiredHold は元待ち後の同一所有者と案件版を確認する。開示操作は行わない。
func (r *Repository) recheckTerminalRequiredHold(c disclosure.Case, b *postingBoard) error {
	if e := r.available(); e != nil {
		return e
	}
	if r.posting[c.Scope.Board] != b {
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

// reconcileTerminalRequiredHold はr.mu下で入り、元所有列待ち中だけ解放する。
// 取消後の未保存参照は元の初回署名を回復する。未完了copyは解除しない。
func (r *Repository) reconcileTerminalRequiredHold(ctx context.Context, c disclosure.Case, b *postingBoard) (disclosure.Case, error) {
	current, e := r.evidenceCases.Get(c.ID)
	if e != nil {
		return c, e
	}
	c = current
	if !terminalRequiredCase(c) {
		return c, nil
	}
	if b == nil || b.requiredHolds == nil {
		if c.Required != nil {
			return c, store.ErrCorrupt
		}
		return c, nil
	}
	source, found, e := r.lookupTerminalRequiredHold(ctx, c, b)
	if e != nil {
		return c, e
	}
	if !found {
		return c, nil
	}
	if c.Required != nil && c.Required.Released != nil {
		return c, nil
	}
	return r.saveAndReleaseTerminalRequiredHold(ctx, c, b, source)
}

// saveAndReleaseTerminalRequiredHold は完成copy検査と終端参照の先行署名後だけ元解除を許可する。
func (r *Repository) saveAndReleaseTerminalRequiredHold(ctx context.Context, c disclosure.Case, b *postingBoard, source requiredTerminalSource) (disclosure.Case, error) {
	release, e := r.reservePrivateLossBytes(1 << 20)
	if e != nil {
		return c, e
	}
	defer release()
	if c.State == "active" {
		if _, e = r.evidenceCases.Records(c, time.Now()); e != nil {
			return c, e
		}
	}
	c, e = r.reconcileTerminalRequiredReference(c, source)
	if e != nil {
		return c, e
	}
	return r.releaseTerminalRequiredSource(ctx, c, b, source.Receipt)
}

// terminalRequiredCase は取消/満了と予約付き完成copyだけを後処理対象にする。
func terminalRequiredCase(c disclosure.Case) bool {
	return c.State == "closed" || c.State == "releasing" || c.State == "active" && c.Required != nil
}

// requiredTerminalSource は同じ元所有列から読んだ現在行・直前active・延長証明。
type requiredTerminalSource struct {
	Receipt app.RequiredHoldReceipt
	Active  app.RequiredHoldReceipt
	Proof   *app.RequiredHoldRenewalReceipt
}

// reconcileTerminalRequiredReference は取消後の延長参照を先行保存し、他は既存初回採用経路を使う。
func (r *Repository) reconcileTerminalRequiredReference(c disclosure.Case, source requiredTerminalSource) (disclosure.Case, error) {
	if c.RequiredExtension != nil && c.RequiredExtension.State == "pending" && c.Required != nil && source.Proof != nil {
		if c.Required.Reservation.SHA != source.Active.SHA {
			return r.evidenceCases.ReconcileRequiredRenewal(c.ID, c.Creator, c.ETag(), *source.Proof, time.Now())
		}
	}
	return r.evidenceCases.ReconcileRequiredReservation(c.ID, c.Creator, c.ETag(), source.Active, time.Now())
}

// lookupTerminalRequiredHold は現在元/最後のactive/延長承認を所有列で読み、復帰後に全署名案件へ照合する。
func (r *Repository) lookupTerminalRequiredHold(ctx context.Context, c disclosure.Case, b *postingBoard) (requiredTerminalSource, bool, error) {
	var source requiredTerminalSource
	var found bool
	e := r.awaitRequiredHoldOwner(ctx, b, func() error {
		var e error
		source, found, e = readTerminalRequiredSource(b.requiredHolds, c.ID)
		return e
	})
	if e != nil {
		return source, found, e
	}
	if e = r.recheckTerminalRequiredHold(c, b); e != nil {
		return source, found, e
	}
	if !found {
		if c.Required != nil {
			return source, found, store.ErrCorrupt
		}
		return source, found, nil
	}
	if e = r.evidenceCases.CheckRequiredRenewal(c, source.Receipt, source.Proof); e != nil {
		return source, found, e
	}
	return source, found, nil
}

// readTerminalRequiredSource は元所有列だけから呼び、解除後も最後のactiveと承認を保持する。
func readTerminalRequiredSource(h *app.RequiredOriginalHolds, id domain.ID) (requiredTerminalSource, bool, error) {
	var result requiredTerminalSource
	receipt, found, e := h.Receipt(id)
	if e != nil || !found {
		return result, found, e
	}
	result.Receipt = receipt
	result.Active, found, e = h.LastActiveReceipt(id)
	if e != nil {
		return result, true, e
	}
	if !found {
		return result, true, store.ErrCorrupt
	}
	proof, exists, e := h.RenewalReceipt(id)
	if e != nil {
		return result, true, e
	}
	if exists {
		result.Proof = &proof
	}
	return result, true, nil
}

// releaseTerminalRequiredSource は照合済み現在元をCAS解除し、版再確認後に解除署名を案件へ保存する。
func (r *Repository) releaseTerminalRequiredSource(ctx context.Context, c disclosure.Case, b *postingBoard, receipt app.RequiredHoldReceipt) (disclosure.Case, error) {
	var released app.RequiredHoldReceipt
	e := r.awaitRequiredHoldOwner(ctx, b, func() error {
		var e error
		released, e = b.requiredHolds.Release(receipt, domain.Time(time.Now().UnixNano()))
		return e
	})
	if e != nil {
		return c, e
	}
	if e = r.recheckTerminalRequiredHold(c, b); e != nil {
		return c, e
	}
	return r.evidenceCases.RecordRequiredRelease(c.ID, c.Creator, c.ETag(), released, time.Now())
}

// cleanupCancelledRequiredHold は元Sync待ちで取消が先行した場合だけ、既存署名終端の後処理を完了する。
func (r *Repository) cleanupCancelledRequiredHold(c disclosure.Case, b *postingBoard) error {
	current, e := r.evidenceCases.Get(c.ID)
	if e != nil {
		return e
	}
	if current.State != "closed" && current.State != "releasing" {
		return nil
	}
	_, e = r.reconcileTerminalRequiredHold(context.Background(), current, b)
	return e
}

// reconcileTerminalRequiredHoldsLocked は現在の終端案件を巡回する。r.muを保持して呼ぶ。
func (r *Repository) reconcileTerminalRequiredHoldsLocked(ctx context.Context) error {
	cases, e := r.evidenceCases.Cases()
	if e != nil {
		return e
	}
	for _, c := range cases {
		if !terminalRequiredCase(c) {
			continue
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if _, e = r.reconcileTerminalRequiredHold(ctx, c, r.posting[c.Scope.Board]); e != nil {
			return e
		}
	}
	return nil
}
