// 保存済みのHTTP照会監査について、署名履歴の対象範囲を検証する。
package disclosure

import (
	"oimobbs/internal/app"
)

// validateHTTPQueryAudit は署名履歴でも、スレッド推定と未選択本文列を拒否する。
func validateHTTPQueryAudit(a Audit) error {
	if a.Action == "http_query" && (a.Case.Scope.Thread != 0 || !app.ValidRejectedColumns(a.Columns)) {
		return ErrInvalid
	}
	return nil
}
