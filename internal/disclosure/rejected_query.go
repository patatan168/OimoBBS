// 未受理の通常期限内照会を既存案件へ署名監査し、保全済み投稿と混同しない。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"time"
)

// RecordRejectedQuery は先行監査だけをSyncする。呼出元はreader53と現在権限を先に確認する。
// 元所有列の待ち後は案件CAS/権限/7日期限を再検査してから接続情報を返す。
func (s *Store) RecordRejectedQuery(id, actor domain.ID, etag, key, purpose string, columns []string, now time.Time) (Case, error) {
	if !app.ValidRejectedColumns(columns) {
		return Case{}, ErrInvalid
	}
	return s.recordLiveQuery(id, actor, "rejected_query", etag, key, purpose, columns, now)
}

// recordLiveQuery は元を待つ前に固定scopeの照会を署名し、再送も現在期限を照合する。
func (s *Store) recordLiveQuery(id, actor domain.ID, action, etag, key, purpose string, columns []string, now time.Time) (Case, error) {
	input := struct {
		Purpose string   `json:"purpose"`
		Columns []string `json:"columns"`
	}{purpose, columns}
	prior, replay, e := s.Replay(id, actor, action, etag, key, input)
	if e != nil {
		return prior, e
	}
	current, e := s.Get(id)
	if e != nil {
		return current, e
	}
	checked := etag
	auditKey := key
	if replay {
		checked = current.ETag()
		auditKey = ""
	}
	c, e := s.AuthorizeState(id, checked, now)
	if e != nil {
		return c, e
	}
	if c.State != "draft" && c.State != "active" && c.State != "partial" {
		return c, ErrConflict
	}
	return s.append(c, actor, action, purpose, columns, etag, auditKey, input, nil, now)
}

// MatchesRejected は案件と元proposalの固定IDへ照合し、別板/別日時の接続を混ぜない。
func MatchesRejected(scope Scope, r app.RejectedEvidence) bool {
	return scopeMatchesRejectedSource(scope, r.Board, r.Thread, r.Committed, r.RecordID)
}
