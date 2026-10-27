// 元回収前に、完成した必須copyの物理存在・hash・両側元署名・固定予約対応を検査する。
package disclosure

import (
	"crypto/ed25519"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"time"
)

// InspectRequiredCompletedCopies は署名照合済み最新案件の期限内完成copyを非変更で検査する。
// 保護期限到達/取消後のcopyは検査対象外。未完了copyの開示認可には使わず、本文を返さない。
func InspectRequiredCompletedCopies(root string, key ed25519.PrivateKey, rows []RequiredCaseInspection, now time.Time) error {
	if len(key) != ed25519.PrivateKeySize || len(rows) > MaxCases {
		return ErrInvalid
	}
	reader := &Store{root: root, key: key}
	for _, row := range rows {
		c := row.Current
		if e := reader.inspectRejectedCompletedCopy(c, now); e != nil {
			return e
		}
		if c.Required == nil || c.State != "active" || c.RetentionUntil() <= domain.Time(now.UnixNano()) {
			continue
		}
		if e := reader.inspectRequiredCompletedCopy(c); e != nil {
			return e
		}
	}
	return nil
}

func (s *Store) inspectRequiredCompletedCopy(c Case) error {
	records, e := s.readHeldRecords(c)
	if e != nil {
		return e
	}
	refs := c.Required.Reservation.Postings
	if len(records) != len(refs) {
		return store.ErrCorrupt
	}
	return nil
}

// verifyHeldCaseRecord は予約付きcopyの全対応を固定参照へ束縛し、旧案件の照合形式を維持する。
func (s *Store) verifyHeldCaseRecord(c Case, record app.AcceptedEvidence) error {
	if c.Required == nil {
		return s.verifyRecord(record)
	}
	for _, ref := range c.Required.Reservation.Postings {
		if ref.Identity.ProposalID == record.RecordID {
			return app.ValidateRequiredHeldCopy(c.Scope.Board, ref, record, 10, s.key.Public().(ed25519.PublicKey))
		}
	}
	return store.ErrCorrupt
}

// inspectRejectedCompletedCopy は通常原本の回収前に案件コピーの存在と署名済みhashを検査する。
func (s *Store) inspectRejectedCompletedCopy(c Case, now time.Time) error {
	if c.Rejected == nil || c.Rejected.State != "active" || c.RetentionUntil() <= domain.Time(now.UnixNano()) {
		return nil
	}
	_, e := s.readRejectedHeldRecords(c)
	return e
}
