// 原本回収が案件の最新署名時刻より過去へ戻らないよう、非変更で時計床を渡す。
package disclosure

import "oimobbs/internal/domain"

// RequiredGCClockFloor は全案件の最新監査を照合した最大時刻を返す。
// 案件排他内で保護集合作成/原本回収まで同じ履歴を保持する。期限回収は実行しない。
func (s *Store) RequiredGCClockFloor() (domain.Time, error) {
	if s.stopped {
		return 0, ErrConflict
	}
	var floor domain.Time
	for id := range s.logs {
		a, e := s.lastAudit(id)
		if e != nil {
			return 0, e
		}
		floor = max(floor, a.At)
	}
	return floor, nil
}
