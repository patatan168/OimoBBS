// 受理操作のないHTTP観測の通常期限内照会を、案件の先行署名監査へ結合する。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"time"
)

// RecordHTTPQuery はreader56先行保存後に板全体の明示期間照会を署名する。
// HTTP観測にはスレッド所属がないため、スレッド指定を推定で広げず拒否する。
func (s *Store) RecordHTTPQuery(id, actor domain.ID, etag, key, purpose string, columns []string, now time.Time) (Case, error) {
	if !app.ValidRejectedColumns(columns) {
		return Case{}, ErrInvalid
	}
	c, e := s.Get(id)
	if e != nil {
		return c, e
	}
	if c.Scope.Thread != 0 {
		return c, ErrInvalid
	}
	return s.recordLiveQuery(id, actor, "http_query", etag, key, purpose, columns, now)
}

// validateHTTPQueryAudit は署名履歴でも、スレッド推定と未選択本文列を拒否する。
func validateHTTPQueryAudit(a Audit) error {
	if a.Action == "http_query" && (a.Case.Scope.Thread != 0 || !app.ValidRejectedColumns(a.Columns)) {
		return ErrInvalid
	}
	return nil
}
