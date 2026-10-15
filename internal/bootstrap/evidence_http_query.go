// 受付前拒否/閲覧のHTTP照会を担当板・再認証・先行案件監査へ接続する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/evidence"
	"slices"
	"time"
)

// queryUnboundHTTP は元待ち中だけ案件排他を解放し、現在権限/CASを確認してから返す。
func (r *Repository) queryUnboundHTTP(ctx context.Context, s adminauth.Session, c disclosure.Case, etag, key, purpose string, columns []string) (disclosure.Case, any, error) {
	if r.optionalStore == nil && (c.HTTP == nil || !c.HTTP.Unbound) {
		return c, nil, &adminFailure{status: 409, code: "OPTIONAL_HTTP_NOT_ENABLED"}
	}
	c, e := r.evidenceCases.RecordHTTPQuery(c.ID, s.Admin, etag, key, purpose, columns, time.Now())
	if e != nil {
		return c, nil, e
	}
	if c.HTTP != nil && c.HTTP.Unbound {
		rows, err := r.evidenceCases.HTTPRecords(c, time.Now())
		if err != nil {
			return c, nil, err
		}
		return c, projectHTTPObservations(c, rows, columns), nil
	}
	return r.queryOrdinaryHTTP(ctx, s, c, columns)
}

// queryOrdinaryHTTP は元7日期限内の観測だけを読み、待ち後の現在認可を検査する。
func (r *Repository) queryOrdinaryHTTP(ctx context.Context, s adminauth.Session, c disclosure.Case, columns []string) (disclosure.Case, any, error) {
	source := r.optionalStore
	var rows []evidence.OptionalEvidence
	e := r.awaitOptionalHoldOwner(func() error {
		var e error
		rows, e = source.QueryUnbound(ctx, evidence.OptionalQueryScope{Board: c.Scope.Board, From: c.Scope.From, To: c.Scope.To, Records: c.Scope.Records}, time.Now())
		return e
	})
	if errors.Is(e, evidence.ErrOptionalQueryLimit) {
		return c, nil, disclosure.ErrLimit
	}
	if e != nil {
		return c, nil, e
	}
	if e = r.recheckHTTPQuery(ctx, s, c, source); e != nil {
		return c, nil, e
	}
	if len(c.Scope.Records) > 0 && len(rows) != len(c.Scope.Records) {
		return c, nil, disclosure.ErrExpired
	}
	return c, projectHTTPObservations(c, rows, columns), nil
}

// recheckHTTPQuery は元所有列待ち後の現在状態・担当権限・再認証・案件CASを照合する。
func (r *Repository) recheckHTTPQuery(ctx context.Context, s adminauth.Session, c disclosure.Case, source *evidence.OptionalStore) error {
	if e := r.available(); e != nil {
		return e
	}
	if r.optionalStore != source {
		return disclosure.ErrConflict
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := r.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true); e != nil {
		return concealRejectedCaseDenial(e)
	}
	if _, e := r.evidenceCases.AuthorizeState(c.ID, c.ETag(), time.Now()); e != nil {
		return e
	}
	return nil
}

// projectHTTPObservations は選択列だけを返し、元期限と案件コピー期限を区別する。
func projectHTTPObservations(c disclosure.Case, rows []evidence.OptionalEvidence, columns []string) []map[string]any {
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		v := row.ProjectUnbound(slices.Contains(columns, "connection"))
		if c.HTTP != nil && c.HTTP.Unbound {
			v["preservation"] = "case_hold"
			v["retention_until_ns"] = c.Until
		}
		result = append(result, v)
	}
	return result
}
