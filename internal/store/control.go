// サイト・板・管理所有単位の制御WAL操作を厳密に検証する。
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"oimobbs/internal/domain"
	"regexp"
	"slices"
)

type Mutation struct {
	Collection       string          `json:"collection"`
	Key              string          `json:"key"`
	ExpectedRevision domain.U64      `json:"expected_revision"`
	Value            json.RawMessage `json:"value"`
	Expires          *domain.Time    `json:"expires_at_ns"`
}
type ControlResult struct {
	Code       string       `json:"code"`
	Targets    []string     `json:"target_ids"`
	RequestKey *domain.Hash `json:"request_key_hmac"`
	Request    *domain.Hash `json:"request_hmac"`
	KeyID      *uint32      `json:"key_id"`
	Expires    *domain.Time `json:"expires_at_ns"`
}
type ControlOperation struct {
	Schema      uint32        `json:"schema"`
	Seq         domain.U64    `json:"seq"`
	Committed   domain.Time   `json:"committed_at_ns"`
	Actor       domain.Actor  `json:"actor"`
	ExpectedSeq domain.U64    `json:"expected_seq"`
	Mutations   []Mutation    `json:"mutations"`
	Result      ControlResult `json:"result"`
}
type ControlRow struct {
	Revision domain.U64
	Expires  *domain.Time
	Value    json.RawMessage
}
type ControlState struct {
	Seq  domain.U64
	Rows map[string]ControlRow
}

var controlCollections = map[uint16][]string{1: {"global_rules", "admin_security", "admin_passkeys", "posting_resources", "waf", "reading_access", "posting_violation", "abuse_guard", "abuse_guard_receipt", "global_posting_policy", "slip_policy", "operations", "operations_receipt", "report_store", "optional_hold_retirement", "case_retirement", "required_gc", "optional_holds", "required_holds", "optional_loss", "optional_http", "network", "site", "rate_policy", "anon_policy", "admin_receipt", "board_directory", "administrator", "cap", "rule", "key_metadata", "token_revocation", "token_issue", "token_reissue", "expiry_watermark"}, 2: {"cap_command", "local_rules", "local_rules_receipt", "post_evidence_query", "carry_retirement", "evidence_checkpoint", "posting_policy", "thread_settings", "thread_settings_receipt", "rule_receipt", "admin_receipt", "board", "key_watermark", "bump_watermark", "board_rule", "request_result"}, 3: {"thread_action", "deletion", "dedup_carry", "rate_carry", "copy_task", "reclamation"}, 4: {"audit_entry", "import_receipt"}, 5: {"report"}, 6: {"job", "child_result"}, 7: {"media"}, 8: {"rejected_connection", "evidence_proposal", "evidence_decision", "thread_admin_proposal", "thread_admin_decision", "attempt", "response", "receipt", "tombstone", "checkpoint", "journal_checkpoint"}, 9: {"case", "hold_item", "export", "transfer"}}
var controlKey = regexp.MustCompile(`^[a-z0-9_]+(?::[a-z0-9_]+)*$`)
var controlCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValueValidator はcollection固有の完全型と業務上の制約を検証する。nilは許可しない。
type ValueValidator func(collection, key string, old json.RawMessage, next json.RawMessage) error

// ApplyControl は全mutationを候補へ適用し、不正な一件があれば全体を拒否する。
func ApplyControl(old ControlState, kind uint16, frame Frame, validate ValueValidator) (ControlState, error) {
	op, e := decodeControlOperation(frame)
	if e != nil {
		return old, e
	}
	return applyControlOperation(old, kind, frame.FirstSeq, op, validate, true)
}

// decodeControlOperation は制御frameの形とJSON完全型を一度だけ検査する。
func decodeControlOperation(frame Frame) (ControlOperation, error) {
	var op ControlOperation
	if len(frame.Records) != 1 || len(frame.Records[0].DAT) != 0 {
		return op, ErrCorrupt
	}
	return decodeStoredControlOperation(frame.Records[0].JSON)
}

// applyControlOperation は解析済み操作の全制約を検査する。
// copyRows=falseは外部から参照されない一括保存候補だけに使用する。
func applyControlOperation(old ControlState, kind uint16, firstSeq uint64, op ControlOperation, validate ValueValidator, copyRows bool) (ControlState, error) {
	return applyControlOperationPrepared(old, kind, firstSeq, op, validate, copyRows, false)
}

// applyControlOperationPrepared は同一呼出し内の独立value検証済み候補にも連番・CAS・業務状態を順番に適用する。
func applyControlOperationPrepared(old ControlState, kind uint16, firstSeq uint64, op ControlOperation, validate ValueValidator, copyRows, valuesVerified bool) (ControlState, error) {
	if validate == nil || len(controlCollections[kind]) == 0 {
		return old, ErrCorrupt
	}
	if op.Schema != 1 || old.Seq == domain.U64(math.MaxUint64) || op.ExpectedSeq != old.Seq || op.Seq != old.Seq+1 || uint64(op.Seq) != firstSeq || len(op.Mutations) < 1 || len(op.Mutations) > 256 || !controlCode.MatchString(op.Result.Code) || op.Result.Targets == nil || len(op.Result.Targets) > 256 {
		return old, ErrCorrupt
	}
	if e := op.Actor.Validate(); e != nil {
		return old, e
	}
	r := op.Result
	if r.RequestKey == nil {
		if r.Request != nil || r.KeyID != nil || r.Expires != nil {
			return old, ErrCorrupt
		}
	} else if r.Request == nil || r.KeyID == nil || *r.KeyID == 0 || r.Expires == nil || op.Committed > domain.Time(math.MaxInt64-86400*1e9) || *r.Expires != op.Committed+domain.Time(86400*1e9) {
		return old, ErrCorrupt
	}
	for _, target := range r.Targets {
		var id domain.ID
		if e := json.Unmarshal([]byte(`"`+target+`"`), &id); e != nil {
			var key domain.U64
			if e = json.Unmarshal([]byte(`"`+target+`"`), &key); e != nil || key == 0 {
				return old, ErrCorrupt
			}
		}
	}
	next := ControlState{Seq: op.Seq, Rows: old.Rows}
	if copyRows {
		next.Rows = make(map[string]ControlRow, len(old.Rows)+len(op.Mutations))
		for k, v := range old.Rows {
			next.Rows[k] = v
		}
	}
	seen := map[string]bool{}
	for _, m := range op.Mutations {
		if !slices.Contains(controlCollections[kind], m.Collection) || len(m.Key) > 160 || !controlKey.MatchString(m.Key) {
			return old, ErrCorrupt
		}
		key := m.Collection + ":" + m.Key
		if seen[key] || old.Rows[key].Revision != m.ExpectedRevision {
			return old, errors.New("control revision conflict")
		}
		seen[key] = true
		value := bytes.TrimSpace(m.Value)
		if len(value) == 0 {
			return old, ErrCorrupt
		}
		if bytes.Equal(value, []byte("null")) && (kind == 1 || kind == 2) {
			if e := validateExpiredControlRemoval(op, m, old.Rows[key]); e != nil {
				return old, e
			}
		}
		if !valuesVerified {
			if e := validate(m.Collection, m.Key, old.Rows[key].Value, value); e != nil {
				return old, e
			}
		}
		if bytes.Equal(value, []byte("null")) {
			delete(next.Rows, key)
		} else {
			if !valuesVerified {
				if e := validateStoredControlValue(m.Collection, m.Key, value); e != nil {
					return old, e
				}
			}
			var expires *domain.Time
			if m.Expires != nil {
				v := *m.Expires
				expires = &v
			}
			next.Rows[key] = ControlRow{Revision: op.Seq, Expires: expires, Value: bytes.Clone(value)}
		}
	}
	return next, nil
}

// NextThreadKey は予約済み高水位を維持し、時計逆行でもキーを再利用しない。
func NextThreadKey(last uint64, unixSeconds int64) (uint64, error) {
	if last == math.MaxUint64 {
		return 0, errors.New("thread keys exhausted")
	}
	next := last + 1
	if unixSeconds > 0 && uint64(unixSeconds) > next {
		next = uint64(unixSeconds)
	}
	return next, nil
}
