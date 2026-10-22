// ZIP作成に対応するHTTP原本の範囲と、事前保全を管理する。
package bootstrap

import (
	"context"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/strictjson"
)

// optionalHTTPHoldScope は案件排他内で固定受理操作と元IDの範囲だけを作り、元所有列を待たない。
func (r *Repository) optionalHTTPHoldScope(c disclosure.Case, now time.Time) (evidence.OptionalQueryScope, error) {
	rows, e := r.evidenceCases.Records(c, now)
	if e != nil {
		return evidence.OptionalQueryScope{}, e
	}
	scope := evidence.OptionalQueryScope{Board: c.Scope.Board, From: c.Scope.From, To: c.Scope.To, Operations: []domain.ID{}}
	for _, row := range rows {
		scope.Operations = append(scope.Operations, row.Operation)
	}
	if len(scope.Operations) == 0 {
		return scope, nil
	}
	if c.HTTP != nil {
		scope.Records, e = r.evidenceCases.HTTPSourceIDs(c, now)
		if e != nil {
			return scope, e
		}
		if len(scope.Records) == 0 {
			return scope, nil
		}
	}
	return scope, nil
}

// optionalHTTPHoldScopeMode は操作なしHTTPを受理操作から推定せず、明示した板/期間で選ぶ。
func (r *Repository) optionalHTTPHoldScopeMode(c disclosure.Case, now time.Time, unbound bool) (evidence.OptionalQueryScope, error) {
	if !unbound {
		return r.optionalHTTPHoldScope(c, now)
	}
	scope := evidence.OptionalQueryScope{Board: c.Scope.Board, From: c.Scope.From, To: c.Scope.To, Records: c.Scope.Records, Operations: []domain.ID{}}
	if c.HTTP != nil {
		var e error
		scope.Records, e = r.evidenceCases.HTTPSourceIDs(c, now)
		return scope, e
	}
	return scope, nil
}

// prepareExportHTTP は案件排他内で呼ぶ。既存の固定HTTP集合と欠測は補完しない。
// 未保全の関連ログだけを既存の署名・予約・コピー経路で保存し、原本期限は延長しない。
func (r *Repository) prepareExportHTTP(ctx context.Context, session adminauth.Session, c disclosure.Case, key, purpose string) (disclosure.Case, error) {
	if c.HTTP != nil || r.optionalStore == nil || c.Rejected != nil {
		return c, nil
	}
	source := r.optionalStore
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return c, e
	}
	e := r.awaitOptionalHoldOwner(func() error {
		if site.MinimumReader < 42 {
			if _, err := r.enableStorageReader(ctx, 42, "http_case_hold_enable"); err != nil {
				return err
			}
		}
		return r.ensureOptionalHoldStorage(ctx)
	})
	if e != nil {
		return c, e
	}
	if e = r.recheckOptionalHold(session, c, source); e != nil {
		return c, e
	}
	holdKey := r.evidenceCases.IDFor(session.Admin, "export-http:"+key).String()
	return r.holdOptionalHTTP(ctx, session, c, c.ETag(), holdKey, purpose)
}

// generateEvidence は要求の再送照合を保ち、初回生成だけ関連HTTPを先に保全する。
func (r *Repository) generateEvidence(ctx context.Context, session adminauth.Session, c disclosure.Case, etag, key, purpose string, columns []string, now time.Time) (disclosure.Case, disclosure.Export, error) {
	return r.evidenceCases.GeneratePrepared(c.ID, session.Admin, etag, key, purpose, columns, now, func(current disclosure.Case) (disclosure.Case, error) {
		return r.prepareExportHTTP(ctx, session, current, key, purpose)
	})
}
