// 受理投稿のないHTTP観測案件を、既存の固定intent・元予約・コピーへ束縛する。
package disclosure

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"slices"
	"time"
)

// PrepareUnboundHTTPHold はreader57の先行保存後、別のdraft案件へHTTP固定intentを保存する。
// 本文/受理投稿保全と混在させず、以後のコピー/元予約は既存のHTTP保全処理を使用する。
func (s *Store) PrepareUnboundHTTPHold(id, actor domain.ID, etag, key, purpose string, site domain.ID, entries []evidence.Entry, now time.Time) (Case, error) {
	return s.prepareHTTPHold(id, actor, etag, key, purpose, site, entries, now, true)
}

// validHTTPHoldStart は案件の種別を初回に固定し、後から別のscopeへ取り替えない。
func validHTTPHoldStart(c Case, unbound bool) bool {
	if !unbound {
		return (c.HTTP == nil || !c.HTTP.Unbound) && (c.State == "active" || c.State == "partial")
	}
	if !emptyHTTPObservationCase(c) {
		return false
	}
	if c.HTTP == nil {
		return c.State == "draft" && len(c.Exports) == 0
	}
	return c.HTTP.Unbound && slices.Contains([]string{"preparing", "active", "partial"}, c.State)
}

// httpRecordMatches は受理投稿対応と、操作なしの板/期間/固定IDを明示して照合する。
func httpRecordMatches(c Case, r evidence.OptionalRecord, ops map[domain.ID]bool) bool {
	if r.Board == nil || *r.Board != c.Scope.Board || r.Received < c.Scope.From || r.Received >= c.Scope.To {
		return false
	}
	if c.HTTP != nil && c.HTTP.Unbound {
		return unboundRecordMatchesScope(c.Scope, r)
	}
	return r.Operation != nil && ops[*r.Operation]
}

// validateUnboundHTTPCase は署名履歴でも受理/未受理本文保全との混在を拒否する。
func validateUnboundHTTPCase(c Case) error {
	if c.HTTP == nil || !c.HTTP.Unbound {
		return nil
	}
	if !emptyHTTPObservationCase(c) {
		return ErrInvalid
	}
	return nil
}

// HoldUnboundHTTP は操作なしHTTPの固定intentを再開する。元予約のない空集合にも同じ完了処理を使う。
func (s *Store) HoldUnboundHTTP(id, actor domain.ID, etag, key, purpose string, site domain.ID, entries []evidence.Entry, now time.Time) (Case, error) {
	return s.holdHTTP(id, actor, etag, key, purpose, site, entries, now, true)
}

// emptyHTTPObservationCase は他の本文/受理保全がないHTTP案件の条件をまとめる。
func emptyHTTPObservationCase(c Case) bool {
	return c.Scope.Thread == 0 && len(c.Items) == 0 && c.Required == nil && c.Rejected == nil
}

// unboundRecordMatchesScope は操作なし裁定と明示したHTTP IDを照合する。
func unboundRecordMatchesScope(scope Scope, r evidence.OptionalRecord) bool {
	return r.Operation == nil && r.Outcome != "accepted" && r.Outcome != "duplicate" && (len(scope.Records) == 0 || slices.Contains(scope.Records, r.ID))
}
