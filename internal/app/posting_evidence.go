// 投稿保存の結合項目と、HTTP収集処理から渡される秘密除去済み記録を検証する。
package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"sync"
	"time"
)

// postingProposal は確定frameを元byteで保持する非公開の保存型。
// Captureの完全な業務スキーマと秘密除去は呼出元のvalidatorで必ず検証する。
type postingProposal struct {
	Owner       domain.ID       `json:"source_owner_id"`
	Day         domain.U64      `json:"source_subkey"`
	Seq         domain.U64      `json:"source_control_seq"`
	ThreadKey   domain.U64      `json:"thread_key"`
	OperationID domain.ID       `json:"operation_id"`
	ThreadSeq   domain.U64      `json:"thread_seq"`
	FrameSHA    domain.Hash     `json:"thread_frame_sha256"`
	Committed   domain.Time     `json:"committed_at_ns"`
	Retention   domain.Time     `json:"retention_until_ns"`
	Frame       string          `json:"prepared_frame_base64"`
	Capture     json.RawMessage `json:"capture"`
}

type postingDecision struct {
	Owner       domain.ID   `json:"source_owner_id"`
	Day         domain.U64  `json:"source_subkey"`
	Seq         domain.U64  `json:"source_control_seq"`
	ThreadKey   domain.U64  `json:"thread_key"`
	OperationID domain.ID   `json:"operation_id"`
	ThreadSeq   domain.U64  `json:"thread_seq"`
	FrameSHA    domain.Hash `json:"thread_frame_sha256"`
	ProposalID  domain.ID   `json:"proposal_id"`
	ProposalSHA domain.Hash `json:"proposal_event_sha256"`
	Committed   domain.Time `json:"committed_at_ns"`
	Retention   domain.Time `json:"retention_until_ns"`
	Outcome     string      `json:"decision"`
	Recovered   bool        `json:"recovered"`
	Decided     domain.Time `json:"decision_at_ns"`
}

// PostingValidator は通常投稿と管理変更のproposal/decisionを種別ごとに検証する。
// capture検証器は収集項目の完全型・秘密除去を検査する。nilでは保存できない。
func PostingValidator(capture func([]byte) error) evidence.PayloadValidator {
	return postingValidator(capture, false)
}

// PostingValidatorConcurrent は並行呼出し可能なcapture検証器をCPU workerから直接呼ぶ。
// captureは入力を変更せず、共有状態への書込みがある場合は内部で排他制御する必要がある。
func PostingValidatorConcurrent(capture func([]byte) error) evidence.PayloadValidator {
	return postingValidator(capture, true)
}

func postingValidator(capture func([]byte) error, concurrent bool) evidence.PayloadValidator {
	// 外部から渡された検査器の呼出しは直列に保つ。frame・payload検査は並行可能。
	var captureMu sync.Mutex
	validateCapture := func(raw []byte) error {
		if concurrent {
			return capture(raw)
		}
		captureMu.Lock()
		defer captureMu.Unlock()
		return capture(raw)
	}
	return func(kind string, b []byte) error {
		switch kind {
		case rejectedConnectionKind:
			return validateRejectedConnection(b)
		case "required_retirement":
			return validatePostingRetirement(b)
		case "evidence_proposal", "thread_admin_proposal":
			var p postingProposal
			if e := strictjson.Decode(b, &p); e != nil {
				return e
			}
			frame, e := base64.StdEncoding.Strict().DecodeString(p.Frame)
			if e != nil || base64.StdEncoding.EncodeToString(frame) != p.Frame {
				return errors.New("invalid proposal frame encoding")
			}
			var f store.Frame
			var op domain.Operation
			if kind == "thread_admin_proposal" {
				f, op, e = administrativeFrame(frame)
				if e != nil {
					return e
				}
				var admin administrativeCapture
				if e = strictjson.Decode(p.Capture, &admin); e != nil {
					return e
				}
				if admin.Schema != 1 || !reflect.DeepEqual(admin.Actor, op.Actor) {
					return errors.New("administrative capture mismatch")
				}
			} else {
				if capture == nil {
					return errors.New("capture validator required")
				}
				if e = validateCapture(p.Capture); e != nil {
					return e
				}
				f, op, e = postingFrame(frame)
				if e != nil {
					return e
				}
				metadata, err := postcapture.ValidateFrameAndMetadata(p.Capture, frame, uint64(p.ThreadKey))
				if err != nil {
					return err
				}
				var observation *evidence.HTTPObservation
				if metadata != nil {
					observation = &metadata.Observation
				} else {
					observation, e = evidence.PostingHTTPObservation(p.Capture)
					if e != nil {
						return e
					}
				}
				if observation != nil {
					if e = observation.ValidatePosting(p.Owner, uint64(p.Day), op); e != nil {
						return e
					}
				}
			}
			if p.ThreadKey == 0 || p.ThreadSeq != op.Revision || p.OperationID != f.Records[0].ID || p.FrameSHA != sha256.Sum256(frame) || p.Committed != op.Committed || p.Retention != postRetention(op.Committed) {
				return errors.New("proposal frame mismatch")
			}
		case "evidence_decision", "thread_admin_decision":
			var d postingDecision
			if e := strictjson.Decode(b, &d); e != nil {
				return e
			}
			if d.ThreadKey == 0 || d.ThreadSeq == 0 || d.Retention != postRetention(d.Committed) || d.Outcome != "accepted" && d.Outcome != "not_accepted" {
				return errors.New("invalid posting decision")
			}
		default:
			return errors.New("unsupported posting evidence kind")
		}
		return nil
	}
}

func postingFrame(prepared []byte) (store.Frame, domain.Operation, error) {
	f, n, e := store.ReadFrame(bytes.NewReader(prepared))
	if e != nil || n != int64(len(prepared)) || len(f.Records) != 1 {
		return f, domain.Operation{}, store.ErrCorrupt
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e == nil && (op.Type != "create" && op.Type != "append" || uint64(op.Revision) != f.FirstSeq || op.Dedup == nil) {
		e = errors.New("only single user posting frames supported")
	}
	return f, op, e
}
func postRetention(committed domain.Time) domain.Time {
	return domain.Time(domain.SixMonths(time.Unix(0, int64(committed))).UnixNano())
}

func (d postingDecision) matches(p postingProposal, event evidence.Event) bool {
	return d.Owner == p.Owner && d.ThreadKey == p.ThreadKey && d.OperationID == p.OperationID && d.ThreadSeq == p.ThreadSeq && d.FrameSHA == p.FrameSHA && d.ProposalID == event.RecordID && d.ProposalSHA == event.EventSHA && d.Committed == p.Committed && d.Retention == p.Retention
}
