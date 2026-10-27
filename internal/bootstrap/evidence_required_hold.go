// 必須原本の案件保全を板所有列の耐久予約・現在認可・固定copyへ接続する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"slices"
	"time"
)

// prepareRequiredHoldStorage は現在認可と保全要求を検査してから板台帳を有効化する。
// 不正な案件版/取消済み要求で通常backup境界を変更しない。
func (r *Repository) prepareRequiredHoldStorage(ctx context.Context, s adminauth.Session, id domain.ID, etag, key, purpose string) error {
	r.mu.Lock()
	c, e := r.evidenceCases.Get(id)
	if e == nil {
		e = r.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true)
	}
	if e == nil {
		e = r.checkRequiredHoldRequest(s, c, etag, key, purpose)
	}
	r.mu.Unlock()
	var denied *adminFailure
	if errors.As(e, &denied) && (denied.code == "BOARD_SCOPE_DENIED" || denied.code == "BOARD_SCOPE_REQUIRED") {
		return &adminFailure{status: 404, code: "EVIDENCE_NOT_FOUND"}
	}
	if e != nil {
		return e
	}
	if c.State == "active" && c.Required == nil {
		return nil
	}
	return r.ensureRequiredHoldStorage(ctx, c.Scope.Board)
}

// checkRequiredHoldRequest は先行有効化前に現在期限/案件版または同一署名要求の再送を確認する。
func (r *Repository) checkRequiredHoldRequest(s adminauth.Session, c disclosure.Case, etag, key, purpose string) error {
	if c.State == "closed" || c.State == "releasing" {
		return disclosure.ErrExpired
	}
	_, replay, e := r.evidenceCases.Replay(c.ID, s.Admin, "hold_intent", etag, key, struct {
		Purpose string `json:"purpose"`
	}{purpose})
	if e != nil {
		return e
	}
	expected := etag
	if replay {
		expected = c.ETag()
	}
	_, e = r.evidenceCases.AuthorizeState(c.ID, expected, time.Now())
	return e
}

// awaitRequiredHoldOwner は案件排他を解放して板所有列を待ち、終了時に取り直す。
func (r *Repository) awaitRequiredHoldOwner(ctx context.Context, b *postingBoard, fn func() error) error {
	return r.awaitOptionalHoldOwner(func() error {
		_, e := b.worker.Submit(ctx, func() (any, error) { return nil, fn() })
		return e
	})
}

// recheckRequiredHold は元待ち後の同一板・現在権限・再認証・案件CAS・期限を検査する。
func (r *Repository) recheckRequiredHold(ctx context.Context, s adminauth.Session, c disclosure.Case, b *postingBoard) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := r.available(); e != nil {
		return e
	}
	if r.posting[c.Scope.Board] != b {
		return store.ErrIncomplete
	}
	if e := r.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true); e != nil {
		return e
	}
	_, e := r.evidenceCases.AuthorizeState(c.ID, c.ETag(), time.Now())
	return e
}

// holdRequiredEvidence はr.mu下で入り、元待ち中だけ解放する。取消時は署名終端を根拠に後処理する。
func (r *Repository) holdRequiredEvidence(ctx context.Context, s adminauth.Session, c disclosure.Case, etag, key, purpose string) (out disclosure.Case, err error) {
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	if e := r.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true); e != nil {
		return c, e
	}
	// 完成済み旧案件の同一要求再送は従来署名を保持する。
	if c.State == "active" && c.Required == nil {
		return r.evidenceCases.Hold(c.ID, s.Admin, etag, key, purpose, nil, time.Now())
	}
	b := r.posting[c.Scope.Board]
	if b == nil || b.requiredHolds == nil {
		return c, store.ErrIncomplete
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.cleanupCancelledRequiredHold(c, b))
		}
	}()
	if c.State == "active" {
		prepared, e := r.evidenceCases.PrepareHold(c.ID, s.Admin, etag, key, purpose, nil, time.Now())
		if e != nil {
			return prepared, e
		}
		return r.completeRequiredHold(ctx, s, prepared, b)
	}
	return r.copyPendingRequiredHold(ctx, s, c, b, etag, key, purpose)
}

// copyPendingRequiredHold は固定対象/予約の照合後に参照を署名し、現在予約付きcopyへ進む。
func (r *Repository) copyPendingRequiredHold(ctx context.Context, s adminauth.Session, c disclosure.Case, b *postingBoard, etag, key, purpose string) (disclosure.Case, error) {
	if e := r.recheckRequiredHold(ctx, s, c, b); e != nil {
		return c, e
	}
	c, records, receipt, e := r.prepareRequiredHold(ctx, s, c, b, etag, key, purpose)
	if e != nil {
		return c, e
	}
	c, e = r.evidenceCases.BindRequiredReservation(c.ID, s.Admin, c.ETag(), receipt, time.Now())
	if e != nil {
		return c, e
	}
	return r.resumeRequiredHold(ctx, s, c, b, records, receipt)
}

// resumeRequiredHold は各copy直前と完了署名前に元現在性・時計・認可・案件版を確認する。
func (r *Repository) resumeRequiredHold(ctx context.Context, s adminauth.Session, c disclosure.Case, b *postingBoard, records []app.AcceptedEvidence, receipt app.RequiredHoldReceipt) (disclosure.Case, error) {
	bound := c
	check := func() error { return r.checkRequiredCopySource(ctx, s, bound, b, receipt) }
	c, e := r.evidenceCases.ResumeRequiredReserved(c.ID, s.Admin, c.ETag(), records, receipt, time.Now(), check)
	if e != nil {
		return c, e
	}
	if c.State != "active" {
		return c, nil
	}
	return r.completeRequiredHold(ctx, s, c, b)
}

// checkRequiredCopySource は板所有列で元参照と時計を確認し、案件排他復帰後に現在認可を検査する。
func (r *Repository) checkRequiredCopySource(ctx context.Context, s adminauth.Session, c disclosure.Case, b *postingBoard, receipt app.RequiredHoldReceipt) error {
	e := r.awaitRequiredHoldOwner(ctx, b, func() error {
		current, found, e := b.requiredHolds.Receipt(c.ID)
		if e != nil {
			return e
		}
		now := domain.Time(time.Now().UnixNano())
		if !found || !sameRequiredSourceReceipt(current, receipt) || current.State != "active" || current.Binding.Until <= now {
			return store.ErrIncomplete
		}
		_, e = b.requiredHolds.Held(domain.ID{}, now)
		return e
	})
	if e != nil {
		return e
	}
	return r.recheckRequiredHold(ctx, s, c, b)
}

// prepareRequiredHold は既存予約を優先して読み、未予約時だけ原本を選び固定intentを先行署名する。
func (r *Repository) prepareRequiredHold(ctx context.Context, s adminauth.Session, c disclosure.Case, b *postingBoard, etag, key, purpose string) (disclosure.Case, []app.AcceptedEvidence, app.RequiredHoldReceipt, error) {
	records, receipt, found, e := r.loadRequiredHoldSelection(ctx, s, c, b)
	if e != nil {
		return c, nil, receipt, e
	}
	c, e = r.evidenceCases.PrepareHold(c.ID, s.Admin, etag, key, purpose, records, time.Now())
	if e != nil {
		return c, nil, receipt, e
	}
	if found {
		return c, records, receipt, nil
	}
	receipt, records, e = r.reserveRequiredHold(ctx, s, c, b, records)
	return c, records, receipt, e
}

// loadRequiredHoldSelection は既存pinを優先し、元待ち後に現在案件を確認して固定集合を返す。
func (r *Repository) loadRequiredHoldSelection(ctx context.Context, s adminauth.Session, c disclosure.Case, b *postingBoard) ([]app.AcceptedEvidence, app.RequiredHoldReceipt, bool, error) {
	var receipt app.RequiredHoldReceipt
	var source requiredTerminalSource
	var found bool
	var records []app.AcceptedEvidence
	e := r.awaitRequiredHoldOwner(ctx, b, func() error {
		var e error
		source, found, e = readTerminalRequiredSource(b.requiredHolds, c.ID)
		receipt = source.Receipt
		if e != nil {
			return e
		}
		if found {
			records, e = b.requiredHolds.Fetch(receipt, b.journals, domain.Time(time.Now().UnixNano()))
		}
		return e
	})
	if e != nil {
		return nil, receipt, found, e
	}
	if e = r.recheckRequiredHold(ctx, s, c, b); e != nil {
		return nil, receipt, found, e
	}
	if found {
		if e = r.evidenceCases.CheckRequiredRenewal(c, receipt, source.Proof); e != nil {
			return nil, receipt, found, e
		}
	}
	if !found {
		records, e = r.collectUnreservedRequiredHold(ctx, s, c, b)
	}
	return records, receipt, found, e
}

// collectUnreservedRequiredHold は未予約の案件だけ原本を読み、再開時には固定ID以外を選ばない。
func (r *Repository) collectUnreservedRequiredHold(ctx context.Context, s adminauth.Session, c disclosure.Case, b *postingBoard) ([]app.AcceptedEvidence, error) {
	if c.Required != nil {
		return nil, store.ErrCorrupt
	}
	var records []app.AcceptedEvidence
	var e error
	scope := c.Scope
	if len(c.Items) > 0 {
		scope.Records = make([]domain.ID, len(c.Items))
		for i, item := range c.Items {
			scope.Records[i] = item.Record
		}
	}
	e = r.awaitOptionalHoldOwner(func() error { var e error; records, e = collectPostingEvidence(ctx, b, scope); return e })
	if e != nil {
		return nil, e
	}
	if e = r.recheckRequiredHold(ctx, s, c, b); e != nil {
		return nil, e
	}
	return records, nil
}

// reserveRequiredHold は固定intentの元予約をSyncし、現在案件へ戻る前に固定集合だけ取得する。
func (r *Repository) reserveRequiredHold(ctx context.Context, s adminauth.Session, c disclosure.Case, b *postingBoard, records []app.AcceptedEvidence) (app.RequiredHoldReceipt, []app.AcceptedEvidence, error) {
	binding, e := r.evidenceCases.RequiredReservationBinding(c, time.Now())
	if e != nil {
		return app.RequiredHoldReceipt{}, nil, e
	}
	var receipt app.RequiredHoldReceipt
	before, after := r.requiredHoldBeforeReserve, r.requiredHoldAfterReserve
	e = r.awaitOptionalHoldOwner(func() error {
		if before != nil {
			before()
		}
		_, e := b.worker.Submit(ctx, func() (any, error) {
			var e error
			receipt, e = b.requiredHolds.Reserve(binding, records, b.journals, domain.Time(time.Now().UnixNano()))
			if e != nil {
				return nil, e
			}
			records, e = b.requiredHolds.Fetch(receipt, b.journals, domain.Time(time.Now().UnixNano()))
			return nil, e
		})
		if after != nil && e == nil {
			after()
		}
		return e
	})
	if e != nil {
		return receipt, nil, e
	}
	if e = r.recheckRequiredHold(ctx, s, c, b); e != nil {
		return receipt, nil, e
	}
	return receipt, records, nil
}

// sameRequiredSourceReceipt は案件別の署名位置と固定集合を完全一致で照合する。
func sameRequiredSourceReceipt(a, b app.RequiredHoldReceipt) bool {
	return a.Binding == b.Binding && a.Sequence == b.Sequence && a.SHA == b.SHA && a.At == b.At && a.State == b.State && slices.Equal(a.Postings, b.Postings)
}

// completeRequiredHold は完成copyを検証して元解除を確定し、返却前に現在認可を再確認する。
func (r *Repository) completeRequiredHold(ctx context.Context, s adminauth.Session, c disclosure.Case, b *postingBoard) (disclosure.Case, error) {
	c, e := r.reconcileTerminalRequiredHold(ctx, c, b)
	if e != nil {
		return c, e
	}
	return c, r.recheckRequiredHold(ctx, s, c, b)
}
