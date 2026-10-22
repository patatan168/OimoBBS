// 未受理原本と案件の固定範囲を照合する。
package disclosure

import "oimobbs/internal/app"

// MatchesRejected は案件と元proposalの固定IDへ照合し、別板/別日時の接続を混ぜない。
func MatchesRejected(scope Scope, r app.RejectedEvidence) bool {
	return scopeMatchesRejectedSource(scope, r.Board, r.Thread, r.Committed, r.RecordID)
}
