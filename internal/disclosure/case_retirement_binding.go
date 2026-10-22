// 起動後の案件作成再送を、siteへ耐久登録された回収HMAC集合に束縛して再出現を防ぐ。
package disclosure

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"time"
)

// BindCaseRetirements は現在siteの登録集合を署名/時計検査して、固定IDの作成再送を禁止する。
// 呼出元は最低reader/現在site登録と所有排他を検査する。途中失敗では禁止集合を変更しない。
// 通常Controlを開けない部分削除は、この操作より先に別の回収所有者で復旧する必要がある。
func (s *Store) BindCaseRetirements(events map[domain.Hash]evidence.Event, reader uint32, now time.Time) error {
	if s.stopped || len(events) != 0 && reader < 51 {
		return ErrInvalid
	}
	retired := make(map[domain.Hash]struct{}, len(events)+len(s.retired))
	for fingerprint := range s.retired {
		retired[fingerprint] = struct{}{}
	}
	for fingerprint, event := range events {
		intent, e := s.VerifyCaseRetirementIntent(event, fingerprint)
		if e != nil {
			return e
		}
		if domain.Time(now.UnixNano()) < intent.At {
			return evidence.ErrRetirementClock
		}
		retired[fingerprint] = struct{}{}
	}
	s.retired = retired
	return nil
}
