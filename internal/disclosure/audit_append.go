// 案件監査の要求検査・署名・Control保存を分離して一行ずつ確定する。
package disclosure

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"time"
)

// append は枠・CAS・署名遷移を検査してから一行をSyncする。保存不確定はStoreを停止する。
func (s *Store) append(c Case, actor domain.ID, action, purpose string, columns []string, etag, key string, input any, transfer *Transfer, now time.Time) (Case, error) {
	if s.stopped {
		return Case{}, store.ErrCorrupt
	}
	if e := s.checkCaseAuditCapacity(c, action); e != nil {
		return Case{}, e
	}
	seq, previous, e := s.caseAuditPosition(c.ID)
	if e != nil {
		return Case{}, e
	}
	c.Revision = domain.U64(seq)
	a, e := s.prepareCaseAudit(c, actor, action, purpose, columns, etag, key, input, transfer, now)
	if e != nil {
		return Case{}, e
	}
	payload, e := json.Marshal(a)
	if e != nil {
		return Case{}, e
	}
	if !s.caseCapacityException(c, action) {
		if e = s.requireCapacity(int64(len(payload))*2 + (16 << 10)); e != nil {
			return Case{}, e
		}
	}
	event, e := evidence.Seal(evidence.Source{Owner: c.ID, Seq: seq}, domain.NewID(), "receipt", payload, previous, 10, s.key)
	if e != nil {
		return Case{}, e
	}
	if e = s.commitCaseAudit(a, event, payload); e != nil {
		return Case{}, e
	}
	return c, nil
}

// prepareCaseAudit は要求再送/固定対象/時計の非変更検査を済ませた監査値を返す。
func (s *Store) prepareCaseAudit(c Case, actor domain.ID, action, purpose string, columns []string, etag, key string, input any, transfer *Transfer, now time.Time) (Audit, error) {
	if columns == nil {
		columns = []string{}
	}
	raw, e := json.Marshal(input)
	if e != nil {
		return Audit{}, e
	}
	a := Audit{Owner: c.ID, Seq: c.Revision, At: domain.Time(now.UnixNano()), Actor: actor, Action: action, Purpose: purpose, Columns: columns, Case: c, Transfer: transfer}
	if key != "" {
		a.RequestKey = s.mac("request-key", actor[:], []byte(key))
		a.Request = s.mac("request", actor[:], []byte(action), []byte(etag), raw)
		if _, exists, err := s.requestAudit(c.ID, a.RequestKey); err != nil {
			return Audit{}, err
		} else if exists {
			return Audit{}, ErrConflict
		}
	}
	if e = validateCaseCompletionAudit(a); e != nil {
		return Audit{}, e
	}
	if e = validateAudit(c.ID, a); e != nil {
		return Audit{}, e
	}
	if e = s.validateCaseAuditTransition(a); e != nil {
		return Audit{}, e
	}
	return a, nil
}

// validateCaseAuditTransition は初回/既存の元参照・延長・時刻の連続性を照合する。
func (s *Store) validateCaseAuditTransition(a Audit) error {
	var last Audit
	if s.logs[a.Owner] != nil {
		v, e := s.lastAudit(a.Owner)
		if e != nil {
			return e
		}
		last = v
	}
	if e := validateCaseMaintenanceTransition(last, a); e != nil {
		return e
	}
	if e := validateExtensionTransition(last.Case, a.Case, a.Action); e != nil {
		return e
	}
	if e := validateHTTPTransition(last.Case.HTTP, a.Case.HTTP, a.Action); e != nil {
		return e
	}
	if e := validateRequiredSourceTransition(last.Case, a.Case, a.Action); e != nil {
		return e
	}
	if a.At < last.At {
		return ErrExpired
	}
	return nil
}

// caseAuditFrame は元署名をControl操作へ包み、適用前に検証できるframeを返す。
func (s *Store) caseAuditFrame(a Audit, event evidence.Event, payload []byte) (store.Frame, error) {
	value, e := json.Marshal(event)
	if e != nil {
		return store.Frame{}, e
	}
	actorRequest := s.mac("audit-actor", payload)
	actorKey := s.mac("audit-operation", event.RecordID[:])
	kid := uint32(10)
	actor := a.Actor
	op := store.ControlOperation{Schema: 1, Seq: a.Seq, ExpectedSeq: a.Seq - 1, Committed: a.At, Actor: domain.Actor{Kind: "admin", ID: &actor, Reason: "evidence_" + a.Action, Request: &actorRequest, Idempotency: &actorKey, KeyID: &kid}, Mutations: []store.Mutation{{Collection: "transfer", Key: event.RecordID.String(), Value: value}}, Result: store.ControlResult{Code: "evidence_saved", Targets: []string{a.Owner.String()}}}
	body, e := json.Marshal(op)
	return store.Frame{FirstSeq: uint64(a.Seq), Records: []store.Record{{ID: event.RecordID, JSON: body}}}, e
}

// commitCaseAudit は型検査済み署名行を確定し、耐久保存後にだけ再送索引を更新する。
func (s *Store) commitCaseAudit(a Audit, event evidence.Event, payload []byte) error {
	logical, e := s.caseAuditFrame(a, event, payload)
	if e != nil {
		return e
	}
	frame, e := store.EncodeFrame(logical)
	if e != nil {
		return e
	}
	if _, e = store.ApplyControl(s.state(a.Owner), 9, logical, s.validator(a.Owner)); e != nil {
		return e
	}
	if e = s.writeCaseAuditFrame(a.Owner, frame); e != nil {
		return e
	}
	if e = s.rememberRequest(a.Owner, a, event); e != nil {
		s.stopped = true
		return e
	}
	return nil
}

// writeCaseAuditFrame は初回作成または既存末尾追記を行い、不確定保存なら停止する。
func (s *Store) writeCaseAuditFrame(id domain.ID, frame []byte) error {
	if s.logs[id] == nil {
		log, e := s.createLog(id, frame)
		if e != nil {
			s.stopped = true
			return e
		}
		s.logs[id] = log
		return nil
	}
	result := s.logs[id].Append(frame)
	if result.Status != store.Durable {
		s.stopped = true
		return result.Err
	}
	return nil
}
