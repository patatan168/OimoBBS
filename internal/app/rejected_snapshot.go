// 未受理の接続・結果だけを案件コピーへ渡し、本文や資格の復元を許さない。
package app

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// rejectedSnapshot は元操作の固定参照だけを持つ。日別保存位置はコピーへ推定/複製しない。
type rejectedSnapshot struct {
	Value     rejectedSnapshotValue `json:"connection_result"`
	SourceID  domain.ID             `json:"source_record_id"`
	SourceSHA domain.Hash           `json:"source_event_sha256"`
}

type rejectedSnapshotValue struct {
	Owner       domain.ID                        `json:"board_id"`
	Thread      domain.U64                       `json:"thread_key"`
	Operation   domain.ID                        `json:"operation_id"`
	Until       domain.Time                      `json:"retention_until_ns"`
	Identity    evidence.RequiredPostingIdentity `json:"posting_identity"`
	Observation *evidence.HTTPObservation        `json:"connection"`
	Missing     string                           `json:"connection_missing_reason"`
	Decided     domain.Time                      `json:"decision_at_ns"`
	Recovered   bool                             `json:"recovered"`
}

// EncodeRejectedSnapshot は日別原本移行前後で同じ接続/結果を同じコピーbytesへ変換する。
// source_record_id/hashは元proposalへの参照であり、移行後の現在原本の保存位置ではない。
func EncodeRejectedSnapshot(r RejectedEvidence) ([]byte, error) {
	if !r.validRejectedProjection() {
		return nil, ErrEvidenceGap
	}
	v := r.value
	snapshot := rejectedSnapshot{Value: rejectedSnapshotValue{v.Owner, v.ThreadKey, v.OperationID, v.Until, v.Identity, v.Observation, v.Missing, v.Decided, v.Recovered}, SourceID: v.Identity.ProposalID, SourceSHA: v.Identity.ProposalSHA}
	return json.Marshal(snapshot)
}

// DecodeRejectedSnapshot は案件の署名済みhash検証後だけ使用する。元署名の検証として使用しない。
func DecodeRejectedSnapshot(raw []byte) (RejectedEvidence, error) {
	var snapshot rejectedSnapshot
	if e := strictjson.Decode(raw, &snapshot); e != nil {
		return RejectedEvidence{}, e
	}
	v := snapshot.Value
	if e := validateRejectedSnapshotValue(v); e != nil {
		return RejectedEvidence{}, e
	}
	if snapshot.SourceID != v.Identity.ProposalID || snapshot.SourceSHA != v.Identity.ProposalSHA {
		return RejectedEvidence{}, ErrEvidenceGap
	}
	value := rejectedConnection{Owner: v.Owner, ThreadKey: v.Thread, OperationID: v.Operation, Until: v.Until, Identity: v.Identity, Observation: v.Observation, Missing: v.Missing, Decided: v.Decided, Recovered: v.Recovered}
	return rejectedEvidenceValue(value, snapshot.SourceID, snapshot.SourceSHA, v.Until), nil
}

// validateRejectedSnapshotValue は元操作と期限/欠測を照合し、source位置を補わない。
func validateRejectedSnapshotValue(v rejectedSnapshotValue) error {
	if v.Owner == (domain.ID{}) || v.Thread != v.Identity.ThreadKey || v.Operation != v.Identity.OperationID || v.Decided < v.Identity.Committed {
		return store.ErrCorrupt
	}
	// Seq=1は共通の操作対応検査への非zero引数で、コピーの元位置には保存しない。
	if e := validatePostingRetirementValue(evidence.RequiredRetirement{Seq: 1, Envelope: evidence.Event{Kind: rejectedConnectionKind, RecordID: rejectedConnectionID(v.Identity)}, Until: v.Until, Identity: v.Identity}); e != nil {
		return e
	}
	if v.Observation == nil {
		if v.Missing != "not_collected" {
			return store.ErrCorrupt
		}
		return nil
	}
	return validateRejectedObservation(rejectedConnection{Owner: v.Owner, Observation: v.Observation, Missing: v.Missing})
}

// RejectedReservedRecords は期限前に署名固定された案件intentの元だけを取得する。
// 呼出元はintent署名/現在案件/CASを検証し、GCと同じ所有排他を共有する。
func RejectedReservedRecords(journals []*evidence.Journal, refs []RejectedSource, captured, until, now domain.Time) ([]RejectedEvidence, error) {
	if captured <= 0 || captured > now || until <= now || len(refs) == 0 || len(refs) > 100 {
		return nil, ErrEvidenceGap
	}
	selected, e := rejectedReservedSelection(refs, captured)
	if e != nil {
		return nil, e
	}
	rows, e := collectRejectedRecords(journals, func(_ domain.ID, _ domain.U64, _ domain.Time, id domain.ID) bool { _, ok := selected[id]; return ok }, 100, now, captured)
	if e != nil {
		return nil, e
	}
	if e := checkRejectedReservedRows(rows, selected); e != nil {
		return nil, e
	}
	return rows, nil
}

// rejectedReservedSelection は期限前参照と重複なしの固定集合を検査する。
func rejectedReservedSelection(refs []RejectedSource, captured domain.Time) (map[domain.ID]RejectedSource, error) {
	selected := map[domain.ID]RejectedSource{}
	for _, ref := range refs {
		if ref.Until <= captured {
			return nil, ErrEvidenceGap
		}
		if _, exists := selected[ref.Record]; exists {
			return nil, ErrEvidenceGap
		}
		selected[ref.Record] = ref
	}
	return selected, nil
}

// checkRejectedReservedRows は対象欠落や両署名hashの差替えを拒否する。
func checkRejectedReservedRows(rows []RejectedEvidence, selected map[domain.ID]RejectedSource) error {
	if len(rows) != len(selected) {
		return ErrEvidenceGap
	}
	for _, row := range rows {
		if row.Source() != selected[row.RecordID] {
			return ErrEvidenceGap
		}
	}
	return nil
}
