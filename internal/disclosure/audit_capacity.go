// 案件監査の終端処理枠を先に確保し、通常操作で解除/回収の署名を締め出さない。
package disclosure

import (
	"oimobbs/internal/domain"
	"time"
)

// MaxCaseAudits は終端枠を含む既存監査列の基準上限。reader49の救済六行を除く。
const MaxCaseAudits uint64 = 4096
const caseTerminalAudits uint64 = 6
const maxRegularCaseAudits = MaxCaseAudits - caseTerminalAudits

// checkCaseAuditCapacity は次の署名行に必要な枠を検査する。呼出元は案件排他を保持する。
func (s *Store) checkCaseAuditCapacity(c Case, action string) error {
	next := uint64(s.state(c.ID).Seq) + 1
	if next == 0 || next > s.caseAuditSequenceLimit(c) {
		return ErrLimit
	}
	if next > regularCaseAuditLimit(c) && !s.caseCapacityException(c, action) {
		return ErrLimit
	}
	return nil
}

// caseFinalizationAudit はアクセス停止/全copy回収と、固定元の終端参照/解除だけを許す。
// 非終端のexport掃除や参照予約を終端枠へ混在させない。
func caseFinalizationAudit(c Case, action string) bool {
	switch action {
	case "release", "expire":
		return caseTerminalState(c) && c.State == "releasing"
	case "cleanup":
		return caseTerminalState(c) && c.State == "closed"
	case "hold_reconciled":
		return caseTerminalState(c)
	case "hold_released":
		return requiredSourceReleased(c)
	case "http_hold_reserved":
		return caseTerminalState(c)
	case "http_hold_released":
		return optionalSourceReleased(c)
	}
	return false
}

// caseAuditPosition は既存正本の最後の署名hashと次seqを取得する。
func (s *Store) caseAuditPosition(id domain.ID) (uint64, domain.Hash, error) {
	if s.logs[id] == nil {
		return 1, domain.Hash{}, nil
	}
	state := s.state(id)
	for _, row := range state.Rows {
		if row.Revision == state.Seq {
			_, event, e := s.readAudit(id, row)
			return uint64(state.Seq) + 1, event.EventSHA, e
		}
	}
	return 0, domain.Hash{}, ErrInvalid
}

func caseTerminalState(c Case) bool {
	return c.Closed > 0 && (c.State == "closed" || c.State == "releasing")
}
func requiredSourceReleased(c Case) bool { return c.Required != nil && c.Required.Released != nil }
func optionalSourceReleased(c Case) bool { return c.HTTP != nil && c.HTTP.Released != nil }

// regularCaseAuditLimit は未回収提出物ごと一行と、終端六行を通常操作から予約する。
func regularCaseAuditLimit(c Case) uint64 {
	limit := maxRegularCaseAudits
	for _, v := range c.Exports {
		if v.State != "removed" {
			limit--
		}
	}
	return limit
}

// EnableCaseCompletionTail は先行保存済みreader49を確認して、旧上限後の終端六行だけを許す。
// 呼出元はsite最低readerをSyncしてから呼ぶ。履歴の削除や通常操作の上限変更は行わない。
func (s *Store) EnableCaseCompletionTail(reader uint32) error {
	if s.stopped || reader < 49 {
		return ErrInvalid
	}
	s.completionTail = true
	return nil
}

func (s *Store) caseAuditSequenceLimit(c Case) uint64 {
	if s.exportCleanupTail {
		return MaxCaseAudits + caseTerminalAudits + uint64(len(c.Exports))
	}
	if s.completionTail {
		return MaxCaseAudits + caseTerminalAudits
	}
	return MaxCaseAudits
}

// validateCaseCompletionAudit は旧上限後を最大六行の終端署名だけへ限定する。
func validateCaseCompletionAudit(a Audit) error {
	if a.Action == exportCleanupAction {
		if uint64(a.Seq) <= MaxCaseAudits || !exportCleanupAudit(a) {
			return ErrInvalid
		}
		return validateCaseTailSequence(a)
	}
	if uint64(a.Seq) <= MaxCaseAudits {
		return nil
	}
	if !caseFinalizationAudit(a.Case, a.Action) {
		return ErrInvalid
	}
	return validateCaseTailSequence(a)
}

func validateCaseTailSequence(a Audit) error {
	if uint64(a.Seq) > MaxCaseAudits+caseTerminalAudits+uint64(len(a.Case.Exports)) {
		return ErrInvalid
	}
	return nil
}

func (s *Store) caseCapacityException(c Case, action string) bool {
	if action == exportCleanupAction {
		return s.exportCleanupTail && !caseTerminalState(c)
	}
	return caseFinalizationAudit(c, action)
}

// NeedsCaseCompletionTail は全案件の最新時計床を非変更確認し、旧上限に達した履歴を検出する。
func (s *Store) NeedsCaseCompletionTail(now domain.Time) (bool, error) {
	if s.stopped {
		return false, ErrInvalid
	}
	needed := false
	for id := range s.logs {
		a, e := s.lastAudit(id)
		if e != nil {
			return false, e
		}
		if now < a.At {
			return false, ErrExpired
		}
		if uint64(a.Seq) >= MaxCaseAudits {
			needed = true
		}
	}
	return needed, nil
}

// checkCaseCleanup は保存枠/時計床/停止状態を物理削除前に検査する。
func (s *Store) checkCaseCleanup(c Case, now time.Time) error {
	return s.checkCaseCleanupAction(c, "cleanup", now)
}

// checkCaseCleanupAction は回収署名の枠と提出物だけの変更を削除前に確認する。
func (s *Store) checkCaseCleanupAction(c Case, action string, now time.Time) error {
	if s.stopped {
		return ErrInvalid
	}
	last, e := s.lastAudit(c.ID)
	if e != nil {
		return e
	}
	if domain.Time(now.UnixNano()) < last.At {
		return ErrExpired
	}
	if action == exportCleanupAction {
		if e = validateExportCleanupProjection(last.Case, c, domain.Time(now.UnixNano())); e != nil {
			return e
		}
	}
	if e = s.checkCaseAuditCapacity(c, action); e != nil {
		return e
	}
	return s.checkCaseTailAppend(Audit{Owner: c.ID, Seq: last.Seq + 1, Action: action, Case: c, At: domain.Time(now.UnixNano())})
}
