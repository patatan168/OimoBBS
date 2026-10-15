// 先行監査済み案件照会へ、同一板・受理操作の期限内HTTP記録だけを付加する。
package bootstrap

import (
	"context"
	"errors"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// collectOptionalHold は既存の投稿コピーに対応する期限内の署名付き原本を取得する。
// 原本回収後の再開は固定intentと既存コピーで進め、空の新履歴を作らない。
func (r *Repository) collectOptionalHold(ctx context.Context, c disclosure.Case, now time.Time) ([]evidence.Entry, error) {
	scope, e := r.optionalHTTPHoldScope(c, now)
	if e != nil {
		return nil, e
	}
	if r.optionalStore == nil {
		if c.HTTP != nil {
			return []evidence.Entry{}, nil
		}
		return nil, &adminFailure{status: 409, code: "OPTIONAL_HTTP_NOT_ENABLED"}
	}
	if len(scope.Operations) == 0 || c.HTTP != nil && len(scope.Records) == 0 {
		return []evidence.Entry{}, nil
	}
	entries, e := r.optionalStore.QuerySigned(ctx, scope, now)
	if errors.Is(e, evidence.ErrOptionalQueryLimit) {
		return nil, disclosure.ErrLimit
	}
	return entries, e
}

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

// attachOptionalEvidence は明示HTTPコピーがないconnection照会へ通常期限の部分観測を追加する。
// 呼出元はRepositoryのmutexと先行案件監査を確定済みで保持する。
func (r *Repository) attachOptionalEvidence(ctx context.Context, c disclosure.Case, rows []map[string]any, now time.Time) error {
	if c.HTTP != nil {
		return nil
	}
	if len(rows) == 0 {
		return nil
	}
	scope := evidence.OptionalQueryScope{Board: c.Scope.Board, From: c.Scope.From, To: c.Scope.To, Operations: []domain.ID{}}
	byOperation := map[domain.ID]map[string]any{}
	for _, row := range rows {
		id, ok := row["operation_id"].(domain.ID)
		if !ok || id == (domain.ID{}) || byOperation[id] != nil {
			return evidence.ErrOptionalQueryScope
		}
		byOperation[id] = row
		scope.Operations = append(scope.Operations, id)
	}
	found := []evidence.OptionalEvidence{}
	status := "not_enabled"
	if r.optionalStore != nil {
		status = "partial_observation"
		var e error
		found, e = r.optionalStore.Query(ctx, scope, now)
		if errors.Is(e, evidence.ErrOptionalQueryLimit) {
			return disclosure.ErrLimit
		}
		if e != nil {
			return e
		}
	}
	for _, row := range rows {
		row["optional_http"] = []evidence.OptionalEvidence{}
		row["optional_http_completeness"] = status
	}
	for _, record := range found {
		row := byOperation[*record.Record.Operation]
		row["optional_http"] = append(row["optional_http"].([]evidence.OptionalEvidence), record)
	}
	for _, row := range rows {
		app.AttachAcceptedHTTPResponse(row)
	}
	return nil
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
