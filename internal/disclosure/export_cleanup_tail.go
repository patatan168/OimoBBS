// 旧上限案件の満了提出物だけを回収し、保全本体と終端六行を維持する。
package disclosure

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"reflect"
	"slices"
)

const exportCleanupAction = "export_cleanup"
const maxCaseExports = 100

// EnableExportCleanup は先行保存済みreader50で提出物ごとの有界回収署名を許す。
func (s *Store) EnableExportCleanup(reader uint32) error {
	if s.stopped || reader < 50 {
		return ErrInvalid
	}
	s.completionTail, s.exportCleanupTail = true, true
	return nil
}

// NeedsExportCleanup は全時計床を検査し、旧上限の非終端案件に満了提出物があるか返す。
func (s *Store) NeedsExportCleanup(now domain.Time) (bool, error) {
	if _, e := s.NeedsCaseCompletionTail(now); e != nil {
		return false, e
	}
	for id := range s.logs {
		a, e := s.lastAudit(id)
		if e != nil {
			return false, e
		}
		if uint64(a.Seq) < MaxCaseAudits || caseTerminalState(a.Case) || caseNeedsExpiration(a.Case, now) {
			continue
		}
		_, expired := expiredCaseExports(a.Case, now)
		if len(expired) != 0 {
			return true, nil
		}
	}
	return false, nil
}

// validateExportCleanupProjection は期限到達した提出物のremoved変更だけを許す。
func validateExportCleanupProjection(old, next Case, at domain.Time) error {
	if !validExportCleanupSource(old, next, at) {
		return store.ErrCorrupt
	}
	expected := old
	expected.Revision = next.Revision
	expected.Exports = slices.Clone(old.Exports)
	changed := 0
	for i, v := range old.Exports {
		state := next.Exports[i].State
		if state == v.State {
			continue
		}
		if state != "removed" || v.State == "removed" || at < v.Until {
			return store.ErrCorrupt
		}
		expected.Exports[i].State = "removed"
		changed++
	}
	if changed == 0 || !reflect.DeepEqual(expected, next) {
		return store.ErrCorrupt
	}
	return nil
}

func validateCaseMaintenanceTransition(old, a Audit) error {
	if e := validateCaseCompletionAudit(a); e != nil {
		return e
	}
	if a.Action == exportCleanupAction {
		return validateExportCleanupProjection(old.Case, a.Case, a.At)
	}
	return nil
}

type caseTailCounts struct{ terminal, exports uint64 }

// observe は救済後の終端六行と提出物100行を別々に数え、相互の枠消費を拒否する。
func (c *caseTailCounts) observe(a Audit) error {
	if uint64(a.Seq) <= MaxCaseAudits {
		return nil
	}
	if a.Action == exportCleanupAction {
		c.exports++
	} else {
		c.terminal++
	}
	if c.terminal > caseTerminalAudits || c.exports > maxCaseExports {
		return ErrLimit
	}
	return nil
}

// checkCaseTailAppend は所有列の次行だけを検査し、履歴再読込みでは全連鎖検査へ委ねる。
func (s *Store) checkCaseTailAppend(a Audit) error {
	log := s.logs[a.Owner]
	if log == nil || a.Seq != log.State().Seq+1 {
		return nil
	}
	if uint64(a.Seq) <= MaxCaseAudits {
		return nil
	}
	if e := s.checkCaseMaintenanceAppend(a); e != nil {
		return e
	}
	var counts caseTailCounts
	for _, row := range log.State().Rows {
		if uint64(row.Revision) <= MaxCaseAudits {
			continue
		}
		old, _, e := s.readAudit(a.Owner, row)
		if e != nil {
			return e
		}
		if e = counts.observe(old); e != nil {
			return e
		}
	}
	return counts.observe(a)
}

func exportCleanupAudit(a Audit) bool {
	return a.Action == exportCleanupAction && !caseTerminalState(a.Case) && len(a.Case.Exports) > 0
}

func (s *Store) exportCleanupAction(c Case) string {
	if uint64(s.state(c.ID).Seq) >= MaxCaseAudits && s.exportCleanupTail {
		return exportCleanupAction
	}
	return "cleanup"
}

// checkCaseMaintenanceAppend は次の提出物回収行を署名保存前に直前状態と照合する。
func (s *Store) checkCaseMaintenanceAppend(a Audit) error {
	if a.Action != exportCleanupAction {
		return nil
	}
	old, e := s.lastAudit(a.Owner)
	if e != nil {
		return e
	}
	return validateExportCleanupProjection(old.Case, a.Case, a.At)
}

// validExportCleanupSource は終端/案件満了を単独ZIP回収へ混在させず、固定集合を維持する。
func validExportCleanupSource(old, next Case, at domain.Time) bool {
	return !caseTerminalState(old) && !caseNeedsExpiration(old, at) && len(old.Exports) == len(next.Exports)
}
