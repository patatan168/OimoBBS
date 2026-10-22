// 通常期限内の未受理記録を受理投稿と区別して、接続と結果だけへ投影する。
package app

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/strictjson"
	"slices"
)

// RejectedEvidence は署名検証済みの未受理接続/結果。入力本文や資格は含まない。
// RecordIDは元proposalの固定ID。SourceIDは通常照会では現在の実署名行、案件コピーでは元proposalへの参照。
type RejectedEvidence struct {
	RecordID      domain.ID
	SourceID      domain.ID
	Board         domain.ID
	Thread        domain.U64
	Committed     domain.Time
	Expires       domain.Time
	SourceExpires domain.Time
	SourceSHA     domain.Hash
	DecisionSHA   domain.Hash
	value         rejectedConnection
	source        evidence.Event
}

// RejectedRecordsInRange は全期間の検証済みJournalから期限内の確定未受理を選ぶ。
// matchは元proposal IDへ適用する。limitは1..100、超過時は部分成功にせず拒否する。
// 24時間回収前は両原本を照合し、回収後は本文なし接続行を参照する。
func RejectedRecordsInRange(journals []*evidence.Journal, match func(domain.ID, domain.U64, domain.Time, domain.ID) bool, limit int, now domain.Time) ([]RejectedEvidence, error) {
	return collectRejectedRecords(journals, match, limit, now, now)
}

// collectRejectedRecords は時計床の現在値と、期限前予約の選択時刻を分けて照合する。
func collectRejectedRecords(journals []*evidence.Journal, match func(domain.ID, domain.U64, domain.Time, domain.ID) bool, limit int, now, selectionTime domain.Time) ([]RejectedEvidence, error) {
	if match == nil || limit < 1 || limit > 100 || now <= 0 {
		return nil, ErrEvidenceGap
	}
	rows := map[domain.ID]RejectedEvidence{}
	decisions := map[domain.ID]evidence.Entry{}
	if e := visitRejectedDecisions(journals, match, rows, decisions, limit, now, selectionTime); e != nil {
		return nil, e
	}
	if e := collectRejectedProposals(journals, rows, decisions, limit); e != nil {
		return nil, e
	}
	if e := checkRejectedDecisionCoverage(decisions, rows); e != nil {
		return nil, e
	}
	result := make([]RejectedEvidence, 0, len(rows))
	for _, row := range rows {
		result = append(result, row)
	}
	slices.SortFunc(result, func(a, b RejectedEvidence) int { return slices.Compare(a.RecordID[:], b.RecordID[:]) })
	return result, nil
}

// collectRejectedDecision は確定未受理の期限内結果だけを選び、同一原本の重複を拒否する。
func collectRejectedDecision(entry evidence.Entry, match func(domain.ID, domain.U64, domain.Time, domain.ID) bool, rows map[domain.ID]RejectedEvidence, decisions map[domain.ID]evidence.Entry, limit int, now domain.Time) error {
	if entry.Event.Kind == rejectedConnectionKind {
		return collectRejectedConnection(entry, match, rows, limit, now)
	}
	if entry.Event.Kind != "evidence_decision" {
		return nil
	}
	var d postingDecision
	if e := strictjson.Decode(entry.Payload, &d); e != nil {
		return e
	}
	if d.Outcome != "not_accepted" || rejectedConnectionUntil(evidence.RequiredPostingIdentity{Committed: d.Committed}) <= now || !match(d.Owner, d.ThreadKey, d.Committed, d.ProposalID) {
		return nil
	}
	if _, exists := decisions[d.ProposalID]; exists {
		return ErrEvidenceGap
	}
	decisions[d.ProposalID] = evidence.Entry{Event: entry.Event, Payload: slices.Clone(entry.Payload)}
	if len(decisions) > limit {
		return ErrEvidenceSelectionLimit
	}
	return nil
}

// collectRejectedProposals は選択結果に対応する原本を照合し、接続と結果だけを保持する。
func collectRejectedProposals(journals []*evidence.Journal, rows map[domain.ID]RejectedEvidence, decisions map[domain.ID]evidence.Entry, limit int) error {
	for _, j := range journals {
		if e := j.Visit(func(entry evidence.Entry) error {
			d, ok := decisions[entry.Event.RecordID]
			if !ok || entry.Event.Kind != "evidence_proposal" {
				return nil
			}
			if _, exists := rows[entry.Event.RecordID]; exists {
				return nil
			}
			row, e := rejectedProposalValue(entry, d)
			if e != nil {
				return e
			}
			rows[row.RecordID] = row
			if len(rows) > limit {
				return ErrEvidenceSelectionLimit
			}
			return nil
		}); e != nil {
			return e
		}
	}
	return nil
}

// rejectedEvidenceValue は署名行の識別子と元操作の固定識別子を分けて投影する。
func rejectedEvidenceValue(v rejectedConnection, id domain.ID, sha domain.Hash, sourceUntil domain.Time) RejectedEvidence {
	return RejectedEvidence{RecordID: v.Identity.ProposalID, SourceID: id, Board: v.Owner, Thread: v.ThreadKey, Committed: v.Identity.Committed, Expires: v.Until, SourceExpires: sourceUntil, SourceSHA: sha, DecisionSHA: v.Identity.DecisionSHA, value: v, source: evidence.Event{RecordID: id, EventSHA: sha}}
}

// Project は未受理と欠測を明示し、connection以外の追加列を拒否する。
func (r RejectedEvidence) Project(columns []string) (map[string]any, error) {
	if !ValidRejectedColumns(columns) || !r.validRejectedProjection() {
		return nil, ErrEvidenceGap
	}
	v := r.value
	out := map[string]any{"record_id": r.RecordID, "source_record_id": r.SourceID, "board_id": r.Board, "thread_key": r.Thread, "operation_id": v.OperationID, "operation_type": v.Identity.Type, "committed_at_ns": r.Committed, "decision_at_ns": v.Decided, "recovered": v.Recovered, "retention_until_ns": r.Expires, "source_retention_until_ns": r.SourceExpires, "source_event_sha256": r.SourceSHA, "decision_event_sha256": r.DecisionSHA, "proposal_event_sha256": v.Identity.ProposalSHA, "public_state": "not_accepted", "completeness": "partial"}
	if slices.Contains(columns, "connection") {
		observation, e := cloneRejectedObservation(v.Observation)
		if e != nil {
			return nil, e
		}
		out["connection"] = observation
		out["connection_missing_reason"] = v.Missing
	}
	return out, nil
}

// ValidRejectedColumns は既定の結果metadataと、明示選択した接続列だけを許可する。
func ValidRejectedColumns(columns []string) bool {
	return len(columns) == 0 || len(columns) == 1 && columns[0] == "connection"
}

// RejectedSource は再開対象を元の両署名hashと7日期限へ固定する本文なし参照。
type RejectedSource struct {
	Record      domain.ID   `json:"record_id"`
	ProposalSHA domain.Hash `json:"proposal_event_sha256"`
	DecisionSHA domain.Hash `json:"decision_event_sha256"`
	Until       domain.Time `json:"retention_until_ns"`
}

// Source は原本から本文なし接続行へ移った後も同じ未受理操作を識別する。
func (r RejectedEvidence) Source() RejectedSource {
	return RejectedSource{r.RecordID, r.value.Identity.ProposalSHA, r.DecisionSHA, r.Expires}
}

// validRejectedProjection は外部で変更された署名対応・結果・範囲を拒否する。
func (r RejectedEvidence) validRejectedProjection() bool {
	v := r.value
	return r.RecordID == v.Identity.ProposalID && r.SourceID == r.source.RecordID && r.SourceID != (domain.ID{}) && r.SourceSHA == r.source.EventSHA && r.SourceSHA != (domain.Hash{}) && r.DecisionSHA == v.Identity.DecisionSHA && v.Identity.Outcome == "not_accepted" && r.rejectedProjectionScopeMatches()
}

// rejectedProjectionScopeMatches は開示範囲と期限を元の非公開投影へ照合する。
func (r RejectedEvidence) rejectedProjectionScopeMatches() bool {
	return r.Board == r.value.Owner && r.Thread == r.value.ThreadKey && r.Committed == r.value.Identity.Committed && r.Expires == r.value.Until && r.SourceExpires == r.value.Until
}

// checkRejectedJournalClock は回収済み時刻より前の照会を拒否する。
func checkRejectedJournalClock(j *evidence.Journal, now domain.Time) error {
	if j == nil {
		return ErrEvidenceGap
	}
	floor, e := j.RequiredRetirementFloor()
	if e != nil {
		return e
	}
	if now < floor {
		return evidence.ErrRetirementClock
	}
	return nil
}

// collectRejectedConnection は本文を持たない期限内の署名行を選ぶ。
func collectRejectedConnection(entry evidence.Entry, match func(domain.ID, domain.U64, domain.Time, domain.ID) bool, rows map[domain.ID]RejectedEvidence, limit int, now domain.Time) error {
	var v rejectedConnection
	if e := strictjson.Decode(entry.Payload, &v); e != nil {
		return e
	}
	if v.Until <= now || !match(v.Owner, v.ThreadKey, v.Identity.Committed, v.Identity.ProposalID) {
		return nil
	}
	if _, exists := rows[v.Identity.ProposalID]; exists {
		return ErrEvidenceGap
	}
	rows[v.Identity.ProposalID] = rejectedEvidenceValue(v, entry.Event.RecordID, entry.Event.EventSHA, v.Until)
	if len(rows) > limit {
		return ErrEvidenceSelectionLimit
	}
	return nil
}

// rejectedProposalValue は両原本の対応を検証し、入力本文を保持しない結果を作る。
func rejectedProposalValue(entry, d evidence.Entry) (RejectedEvidence, error) {
	i, e := PostingRetirementIdentity(entry, d)
	if e != nil {
		return RejectedEvidence{}, e
	}
	var p postingProposal
	if e = strictjson.Decode(entry.Payload, &p); e != nil {
		return RejectedEvidence{}, e
	}
	v, e := buildRejectedConnection(i, p.Capture)
	if e != nil {
		return RejectedEvidence{}, e
	}
	var decision postingDecision
	if e = strictjson.Decode(d.Payload, &decision); e != nil {
		return RejectedEvidence{}, e
	}
	v.Owner, v.Day, v.Seq = p.Owner, p.Day, p.Seq
	v.Decided, v.Recovered = decision.Decided, decision.Recovered
	return rejectedEvidenceValue(v, entry.Event.RecordID, entry.Event.EventSHA, v.Until), nil
}

// cloneRejectedObservation は呼出元の編集が後続照会の署名対応を変えないよう複製する。
func cloneRejectedObservation(observation *evidence.HTTPObservation) (*evidence.HTTPObservation, error) {
	if observation == nil {
		return nil, nil
	}
	raw, e := json.Marshal(observation)
	if e != nil {
		return nil, e
	}
	var copy evidence.HTTPObservation
	if e = strictjson.Decode(raw, &copy); e != nil {
		return nil, e
	}
	return &copy, nil
}

// checkRejectedDecisionCoverage は対象原本の欠落を空の成功結果へ置換しない。
func checkRejectedDecisionCoverage(decisions map[domain.ID]evidence.Entry, rows map[domain.ID]RejectedEvidence) error {
	for id := range decisions {
		if _, found := rows[id]; !found {
			return ErrEvidenceGap
		}
	}
	return nil
}

// visitRejectedDecisions は各日列の時計床を確認して、最初に未受理結果を集める。
func visitRejectedDecisions(journals []*evidence.Journal, match func(domain.ID, domain.U64, domain.Time, domain.ID) bool, rows map[domain.ID]RejectedEvidence, decisions map[domain.ID]evidence.Entry, limit int, now, selectionTime domain.Time) error {
	for _, j := range journals {
		if e := checkRejectedJournalClock(j, now); e != nil {
			return e
		}
		if e := j.Visit(func(entry evidence.Entry) error {
			return collectRejectedDecision(entry, match, rows, decisions, limit, selectionTime)
		}); e != nil {
			return e
		}
	}
	return nil
}
