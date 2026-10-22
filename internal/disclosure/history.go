// 起動時に署名連鎖を一度検証し、通常の一覧と再送では必要な台帳行だけを読む。
package disclosure

import (
	"crypto/ed25519"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"sort"
)

// readAudit は一つの保存行の署名・source・完全スキーマを照合する。
func (s *Store) readAudit(id domain.ID, row store.ControlRow) (Audit, evidence.Event, error) {
	var event evidence.Event
	var a Audit
	if strictjson.Decode(row.Value, &event) != nil {
		return a, event, store.ErrCorrupt
	}
	raw, e := evidence.Verify(evidence.Source{Owner: id, Seq: uint64(row.Revision)}, event, event.PreviousSHA, 10, s.key.Public().(ed25519.PublicKey))
	if e != nil || strictjson.Decode(raw, &a) != nil || validateAudit(id, a) != nil {
		return a, event, store.ErrCorrupt
	}
	return a, event, nil
}

// lastAudit は最新seqの保存行だけを復号し、過去の案件全体を複製しない。
func (s *Store) lastAudit(id domain.ID) (Audit, error) {
	a, _, e := s.lastAuditEvent(id)
	return a, e
}

// lastAuditEvent は最新行の案件と署名envelopeを同時に照合する。
func (s *Store) lastAuditEvent(id domain.ID) (Audit, evidence.Event, error) {
	log := s.logs[id]
	if log == nil {
		return Audit{}, evidence.Event{}, os.ErrNotExist
	}
	state := log.State()
	for _, row := range state.Rows {
		if row.Revision == state.Seq {
			return s.readAudit(id, row)
		}
	}
	return Audit{}, evidence.Event{}, store.ErrCorrupt
}

// walkHistory は起動・停止検査用に全署名連鎖を順に照合する。visitへ渡した値は所有単位の現在値を変更しない。
func (s *Store) walkHistory(id domain.ID, state store.ControlState, visit func(Audit, evidence.Event) error) error {
	rows := make([]store.ControlRow, 0, len(state.Rows))
	for _, row := range state.Rows {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Revision < rows[j].Revision })
	if len(rows) == 0 || uint64(len(rows)) != uint64(state.Seq) {
		return store.ErrCorrupt
	}
	var previous Audit
	var previousSHA domain.Hash
	var counts caseTailCounts
	for i, row := range rows {
		if row.Revision != domain.U64(i+1) {
			return store.ErrCorrupt
		}
		a, event, e := s.readAudit(id, row)
		if e != nil {
			return e
		}
		if e = validateCaseHistoryStep(previous, previousSHA, a, event); e != nil {
			return e
		}
		if e = counts.observe(a); e != nil {
			return e
		}
		if e = visit(a, event); e != nil {
			return e
		}
		previous, previousSHA = a, event.EventSHA
	}

	return nil
}

// validateCaseHistoryStep は署名連鎖/案件時計/元参照と有界終端列を照合する。
func validateCaseHistoryStep(previous Audit, sha domain.Hash, a Audit, event evidence.Event) error {
	if event.PreviousSHA != sha {
		return store.ErrCorrupt
	}
	if previous.Seq != 0 && (a.At < previous.At || a.Case.Created != previous.Case.Created) {
		return store.ErrCorrupt
	}
	if e := validateCaseMaintenanceTransition(previous, a); e != nil {
		return e
	}
	if e := validateRejectedHoldTransition(previous.Case, a.Case, a.Action); e != nil {
		return e
	}
	if e := validateRejectedExportTransition(previous.Case, a.Case, a.Action); e != nil {
		return e
	}
	if e := validateExtensionTransition(previous.Case, a.Case, a.Action); e != nil {
		return e
	}
	if e := validateHTTPTransition(previous.Case.HTTP, a.Case.HTTP, a.Action); e != nil {
		return e
	}
	return validateRequiredSourceTransition(previous.Case, a.Case, a.Action)
}

// rememberRequest は耐久保存済み要求HMACと行IDを索引化し、同一要求の重複行を破損として拒否する。
func (s *Store) rememberRequest(id domain.ID, a Audit, event evidence.Event) error {
	if a.RequestKey == (domain.Hash{}) {
		return nil
	}
	if s.requests[id] == nil {
		s.requests[id] = map[domain.Hash]domain.ID{}
	}
	if _, exists := s.requests[id][a.RequestKey]; exists {
		return store.ErrCorrupt
	}
	s.requests[id][a.RequestKey] = event.RecordID
	return nil
}

// requestAudit は再送の照合に必要な一行を索引から取得して再検証する。
func (s *Store) requestAudit(id domain.ID, key domain.Hash) (Audit, bool, error) {
	eventID, found := s.requests[id][key]
	if !found {
		return Audit{}, false, nil
	}
	row, found := s.logs[id].State().Rows["transfer:"+eventID.String()]
	if !found {
		return Audit{}, false, store.ErrCorrupt
	}
	a, _, e := s.readAudit(id, row)
	return a, true, e
}
