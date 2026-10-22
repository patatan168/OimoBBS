// 署名済み投稿proposalと受理decisionを照合し、制限領域向けの固定集合を取り出す。
package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
)

var ErrEvidenceSelectionLimit = errors.New("evidence selection exceeds record limit")

// AcceptedEvidence は原本の対応情報。公開ルーターへ渡してはならない。
type AcceptedEvidence struct {
	RecordID  domain.ID      `json:"record_id"`
	Board     domain.ID      `json:"board_id"`
	Thread    domain.U64     `json:"thread_key"`
	Operation domain.ID      `json:"operation_id"`
	Post      uint32         `json:"post_number"`
	Committed domain.Time    `json:"committed_at_ns"`
	Expires   domain.Time    `json:"retention_until_ns"`
	Proposal  evidence.Entry `json:"proposal"`
	Decision  evidence.Entry `json:"decision"`
}

// AcceptedRecords は署名検証済みjournalの受理対応を検査する。未確定proposalは返さない。
func AcceptedRecords(journals []*evidence.Journal) ([]AcceptedEvidence, error) {
	return AcceptedRecordsInRange(journals, func(domain.ID, domain.U64, domain.Time, domain.ID) bool { return true }, 0)
}

// AcceptedRecordsInRange は対象proposalだけを複製し、照会時の本文RAMと集合件数を制限する。
func AcceptedRecordsInRange(journals []*evidence.Journal, match func(domain.ID, domain.U64, domain.Time, domain.ID) bool, limit int) ([]AcceptedEvidence, error) {
	return acceptedRecordsFiltered(journals, match, nil, limit)
}

// acceptedRecordsFiltered は所有列内で原本条件を先に絞り、非対象の本文コピーを避ける。
func acceptedRecordsFiltered(journals []*evidence.Journal, match func(domain.ID, domain.U64, domain.Time, domain.ID) bool, filter func(postingProposal) (bool, error), limit int) ([]AcceptedEvidence, error) {
	proposals := map[domain.ID]evidence.Entry{}
	decisions := []evidence.Entry{}
	// レス選択では未受理proposalを件数枠へ入れない。同じ番号の保存失敗後の再投稿を区別する。
	accepted := map[domain.ID]bool{}
	selectedBytes := 0
	if filter != nil {
		for _, j := range journals {
			if err := j.Visit(func(entry evidence.Entry) error {
				if entry.Event.Kind != "evidence_decision" {
					return nil
				}
				var d postingDecision
				if err := strictjson.Decode(entry.Payload, &d); err != nil {
					return err
				}
				if d.Outcome == "accepted" && match(d.Owner, d.ThreadKey, d.Committed, d.ProposalID) {
					accepted[d.ProposalID] = true
				}
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	for _, j := range journals {
		if e := j.Visit(func(entry evidence.Entry) error {
			if entry.Event.Kind != "evidence_proposal" {
				return nil
			}
			if filter != nil && !accepted[entry.Event.RecordID] {
				return nil
			}
			var p postingProposal
			if e := strictjson.Decode(entry.Payload, &p); e != nil {
				return e
			}
			if !match(p.Owner, p.ThreadKey, p.Committed, entry.Event.RecordID) {
				return nil
			}
			if filter != nil {
				selected, err := filter(p)
				if err != nil {
					return err
				}
				if !selected {
					return nil
				}
			}
			if filter != nil {
				selectedBytes += len(entry.Payload)
				if selectedBytes > 8<<20 {
					return ErrEvidenceSelectionLimit
				}
			}
			if limit > 0 && len(proposals) >= limit {
				return ErrEvidenceSelectionLimit
			}
			proposals[entry.Event.RecordID] = evidence.Entry{Event: entry.Event, Payload: slices.Clone(entry.Payload)}
			return nil
		}); e != nil {
			return nil, e
		}
	}
	for _, j := range journals {
		if e := j.Visit(func(entry evidence.Entry) error {
			if entry.Event.Kind != "evidence_decision" {
				return nil
			}
			var d postingDecision
			if e := strictjson.Decode(entry.Payload, &d); e != nil {
				return e
			}
			if _, ok := proposals[d.ProposalID]; ok {
				decisions = append(decisions, evidence.Entry{Event: entry.Event, Payload: slices.Clone(entry.Payload)})
			}
			return nil
		}); e != nil {
			return nil, e
		}
	}

	rows := []AcceptedEvidence{}
	seen := map[domain.ID]bool{}
	for _, entry := range decisions {
		var d postingDecision
		if e := strictjson.Decode(entry.Payload, &d); e != nil {
			return nil, e
		}
		if d.Outcome != "accepted" {
			continue
		}
		source, ok := proposals[d.ProposalID]
		var p postingProposal
		if !ok || strictjson.Decode(source.Payload, &p) != nil || !d.matches(p, source.Event) || seen[p.OperationID] {
			return nil, ErrEvidenceGap
		}
		frame, e := base64.StdEncoding.Strict().DecodeString(p.Frame)
		if e != nil {
			return nil, e
		}
		f, _, e := store.ReadFrame(bytes.NewReader(frame))
		if e != nil || len(f.Records) != 1 {
			return nil, store.ErrCorrupt
		}
		op, e := domain.ParseOperation(f.Records[0].JSON)
		if e != nil || op.Dedup == nil {
			return nil, store.ErrCorrupt
		}
		seen[p.OperationID] = true
		rows = append(rows, AcceptedEvidence{source.Event.RecordID, p.Owner, p.ThreadKey, p.OperationID, op.Dedup.PostNumber, p.Committed, p.Retention, source, entry})
	}
	return rows, nil
}

// Project は対応・結果・保存時環境のメタデータと選択列を返す。
// 元署名は部分列の証明として同梱しない。
func (r AcceptedEvidence) Project(columns []string) (map[string]any, error) {
	if !ValidAcceptedColumns(columns) {
		return nil, ErrEvidenceGap
	}
	out := map[string]any{"record_id": r.RecordID, "board_id": r.Board, "thread_key": r.Thread, "operation_id": r.Operation, "post_number": r.Post, "committed_at_ns": r.Committed, "retention_until_ns": r.Expires, "source_event_sha256": r.Proposal.Event.EventSHA, "source_control_seq": sourceSequence(r.Proposal.Payload), "public_state": "unknown", "completeness": "partial"}
	var p postingProposal
	if e := strictjson.Decode(r.Proposal.Payload, &p); e != nil {
		return nil, e
	}
	result, e := projectAcceptedResult(r, p)
	if e != nil {
		return nil, e
	}
	out["result"] = result
	var capture map[string]json.RawMessage
	if e := json.Unmarshal(p.Capture, &capture); e != nil {
		return nil, e
	}
	obs, e := evidence.PostingHTTPObservation(p.Capture)
	if e != nil {
		return nil, e
	}
	out["environment"], e = projectAcceptedEnvironment(p.Capture, obs)
	if e != nil {
		return nil, e
	}
	for _, column := range columns {
		switch column {
		case "connection":
			out[column] = obs
			out["identity"], out["time"], e = projectAcceptedRequestMetadata(r, p, obs, result)
			if e != nil {
				return nil, e
			}
			if obs == nil {
				out["connection_missing_reason"] = "not_recorded_in_capture"
			}
			out["client"] = projectAcceptedClient(obs)
			cookie, err := projectAcceptedCookie(capture)
			if err != nil {
				return nil, err
			}
			out["cookie"] = cookie
			out["request"] = projectAcceptedHTTPRequest(obs)
		case "content":
			if raw, ok := capture["input"]; ok {
				out[column], e = projectAcceptedContent(p, raw)
				if e != nil {
					return nil, e
				}
			} else {
				out[column] = nil
			}
		}
	}
	return out, nil
}
func sourceSequence(raw []byte) domain.U64 {
	var v struct {
		Seq domain.U64 `json:"source_control_seq"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.Seq
}

// ValidAcceptedColumns は受理記録の接続・本文だけを許可し、廃止項目・重複・未知列を拒否する。
func ValidAcceptedColumns(columns []string) bool {
	if len(columns) > 2 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range columns {
		if seen[v] || !slices.Contains([]string{"connection", "content"}, v) {
			return false
		}
		seen[v] = true
	}
	return true
}
