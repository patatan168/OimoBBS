// 未受理の通常期限内照会/提出を既存案件・担当権限・先行監査へ接続する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"os"
	"reflect"
	"slices"
	"time"
)

func (r *Repository) prepareRejectedEvidenceAction(ctx context.Context, s adminauth.Session, id domain.ID, permission string, columns []string, minimum uint32) error {
	if !app.ValidRejectedColumns(columns) {
		return disclosure.ErrInvalid
	}
	r.mu.Lock()
	c, e := r.evidenceCases.Get(id)
	if e == nil {
		e = r.authorizeEvidence(s, permission, c.Scope.Board, true)
	}
	if e == nil && minimum == 56 {
		if c.Scope.Thread != 0 {
			e = disclosure.ErrInvalid
		} else if r.optionalStore == nil && (c.HTTP == nil || !c.HTTP.Unbound) {
			e = &adminFailure{status: 409, code: "OPTIONAL_HTTP_NOT_ENABLED"}
		}
	}
	r.mu.Unlock()
	if e != nil {
		return concealRejectedCaseDenial(e)
	}
	_, e = r.enableStorageReader(ctx, minimum, "rejected_evidence_enable")
	return e
}

func concealRejectedCaseDenial(e error) error {
	var denied *adminFailure
	if errors.As(e, &denied) && (denied.code == "BOARD_SCOPE_DENIED" || denied.code == "BOARD_SCOPE_REQUIRED") {
		return &adminFailure{status: 404, code: "EVIDENCE_NOT_FOUND"}
	}
	return e
}

// collectRejectedEvidence は原本の本文を返さず、案件mutexを解放して板所有者から投影する。
func (r *Repository) collectRejectedEvidence(ctx context.Context, scope disclosure.Scope) ([]app.RejectedEvidence, error) {
	b := r.posting[scope.Board]
	if b == nil {
		return nil, os.ErrNotExist
	}
	var rows []app.RejectedEvidence
	e := r.awaitOptionalHoldOwner(func() error {
		result, e := b.worker.Submit(ctx, func() (any, error) {
			return app.RejectedRecordsInRange(requiredGCJournals(b), func(owner domain.ID, key domain.U64, at domain.Time, id domain.ID) bool {
				return owner == scope.Board && (scope.Thread == 0 || key == scope.Thread) && at >= scope.From && at < scope.To && (len(scope.Records) == 0 || slices.Contains(scope.Records, id))
			}, disclosure.MaxRecords, domain.Time(time.Now().UnixNano()))
		})
		if e != nil {
			return e
		}
		rows = result.([]app.RejectedEvidence)
		return nil
	})
	if errors.Is(e, app.ErrEvidenceSelectionLimit) {
		return nil, disclosure.ErrLimit
	}
	return rows, e
}

func (r *Repository) recheckRejectedEvidence(s adminauth.Session, c disclosure.Case, permission string, rows []app.RejectedEvidence) error {
	if e := r.available(); e != nil {
		return e
	}
	if e := r.authorizeEvidence(s, permission, c.Scope.Board, true); e != nil {
		return concealRejectedCaseDenial(e)
	}
	current, e := r.evidenceCases.AuthorizeState(c.ID, c.ETag(), time.Now())
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(current.Scope, c.Scope) {
		return disclosure.ErrRevision
	}
	for _, row := range rows {
		if row.Expires <= domain.Time(time.Now().UnixNano()) && !rejectedCaseOwnsSource(c, row) {
			return disclosure.ErrExpired
		}
	}
	return nil
}

func (r *Repository) queryRejectedEvidence(ctx context.Context, s adminauth.Session, c disclosure.Case, etag, key, purpose string, columns []string) (disclosure.Case, any, error) {
	c, e := r.evidenceCases.RecordRejectedQuery(c.ID, s.Admin, etag, key, purpose, columns, time.Now())
	if e != nil {
		return c, nil, e
	}
	rows, e := r.rejectedEvidenceRows(ctx, c, c.Scope)
	if e != nil {
		return c, nil, e
	}
	if e = r.recheckRejectedEvidence(s, c, "evidence.manage", rows); e != nil {
		return c, nil, e
	}
	if len(c.Scope.Records) > 0 && len(rows) != len(c.Scope.Records) {
		return c, nil, disclosure.ErrExpired
	}
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		v, e := row.Project(columns)
		if e != nil {
			return c, nil, e
		}
		v["preservation"] = "ordinary_retention"
		if c.Rejected != nil && c.Rejected.State == "active" {
			v["preservation"] = "case_hold"
			v["held_until_ns"] = c.RetentionUntil()
		}
		result = append(result, v)
	}
	return c, result, nil
}

func (r *Repository) generateRejectedEvidence(ctx context.Context, s adminauth.Session, c disclosure.Case, etag, key, purpose string, columns []string) (disclosure.Case, disclosure.Export, error) {
	scope, ready := rejectedExportCollectionScope(c, r.evidenceCases.IDFor(s.Admin, "rejected-export:"+key))
	var rows []app.RejectedEvidence
	var e error
	if !ready {
		rows, e = r.rejectedEvidenceRows(ctx, c, scope)
	}
	if e != nil {
		return c, disclosure.Export{}, e
	}
	if e = r.recheckRejectedEvidence(s, c, "evidence.manage", rows); e != nil {
		return c, disclosure.Export{}, e
	}
	return r.evidenceCases.GenerateRejected(c.ID, s.Admin, etag, key, purpose, columns, rows, time.Now())
}

func (r *Repository) resumeRejectedEvidence(ctx context.Context, s adminauth.Session, c disclosure.Case, export domain.ID, etag, key, purpose string) (disclosure.Case, disclosure.Export, error) {
	scope, ready := rejectedExportCollectionScope(c, export)
	var rows []app.RejectedEvidence
	var e error
	if !ready {
		rows, e = r.rejectedEvidenceRows(ctx, c, scope)
	}
	if e != nil {
		return c, disclosure.Export{}, e
	}
	if e = r.recheckRejectedEvidence(s, c, "evidence.manage", rows); e != nil {
		return c, disclosure.Export{}, e
	}
	return r.evidenceCases.ResumeRejectedExport(c.ID, export, s.Admin, etag, key, purpose, rows, time.Now())
}

// rejectedExportCollectionScope は再開時に初回の固定IDだけを元所有列へ照会する。
func rejectedExportCollectionScope(c disclosure.Case, id domain.ID) (disclosure.Scope, bool) {
	scope := c.Scope
	for _, v := range c.Exports {
		if v.ID != id || v.Kind != "not_accepted" {
			continue
		}
		scope.Records = make([]domain.ID, 0, len(v.RejectedSources))
		for _, ref := range v.RejectedSources {
			scope.Records = append(scope.Records, ref.Record)
		}
		return scope, v.State != "preparing"
	}
	return scope, false
}

func isRejectedExport(c disclosure.Case, id domain.ID) bool {
	for _, v := range c.Exports {
		if v.ID == id {
			return v.Kind == "not_accepted"
		}
	}
	return false
}

// rejectedCaseOwnsSource は署名済み期限前intent/完成コピーの固定元だけを期限後に許可する。
func rejectedCaseOwnsSource(c disclosure.Case, row app.RejectedEvidence) bool {
	return c.Rejected != nil && c.Rejected.State != "removed" && slices.Contains(c.Rejected.Sources, row.Source())
}

// rejectedEvidenceRows は案件コピーと通常期限内原本を混ぜず、現在の保全状態で選ぶ。
func (r *Repository) rejectedEvidenceRows(ctx context.Context, c disclosure.Case, scope disclosure.Scope) ([]app.RejectedEvidence, error) {
	if c.Rejected != nil {
		return r.evidenceCases.RejectedRecords(c, time.Now())
	}
	return r.collectRejectedEvidence(ctx, scope)
}
