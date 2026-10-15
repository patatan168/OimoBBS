// connection選択へ保存済み要求IDと時計観測をまとめ、未保存時刻を区別する。
package app

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// projectAcceptedRequestMetadata は観測時の要求IDと受理原本の全投稿番号を返す。
// 接続観測がない旧記録からIDや受付時刻を補完しない。
func projectAcceptedRequestMetadata(r AcceptedEvidence, p postingProposal, obs *evidence.HTTPObservation, result map[string]any) (map[string]any, map[string]any, error) {
	if obs == nil {
		return nil, nil, nil
	}
	if obs.BoardID != p.Owner {
		return nil, nil, ErrEvidenceGap
	}
	_, op, e := acceptedEvidenceFrame(p)
	if e != nil {
		return nil, nil, e
	}
	posts, _, e := acceptedPublicPosts(op)
	if e != nil {
		return nil, nil, e
	}
	numbers := make([]uint32, 0, len(posts))
	for _, post := range posts {
		numbers = append(numbers, post.Number)
	}
	identity := map[string]any{"record_id": r.RecordID, "operation_id": p.OperationID, "request_id": obs.RequestID, "connection_id": obs.ConnectionID, "process_boot_id": obs.BootID, "site_id": obs.SiteID, "board_id": obs.BoardID, "thread_key": p.ThreadKey, "post_numbers": numbers, "site_instance_id": obs.InstanceID}
	return identity, acceptedRequestTime(p.Committed, obs, result), nil
}

// acceptedRequestTime は時計の観測値と欠測理由を維持し、prepare/応答完了を推定しない。
func acceptedRequestTime(committed domain.Time, obs *evidence.HTTPObservation, result map[string]any) map[string]any {
	missing := []evidence.MissingField{
		{Field: "prepared_at_ns", Reason: "not_recorded_in_capture"},
		{Field: "response_finished_at_ns", Reason: "requires_separate_http_record"},
	}
	for _, field := range obs.MissingFields {
		if field.Field == "clock_offset_ms" || field.Field == "clock_observed_at_ns" {
			missing = append(missing, field)
		}
	}
	return map[string]any{"received_at_ns": obs.Received, "body_completed_at_ns": obs.BodyCompleted, "prepared_at_ns": nil, "committed_at_ns": committed, "decision_at_ns": result["decision_at_ns"], "response_finished_at_ns": nil, "monotonic_elapsed_ns": obs.MonotonicElapsed, "clock_status": obs.ClockStatus, "clock_source": obs.ClockSource, "clock_offset_ms": obs.ClockOffsetMS, "clock_observed_at_ns": obs.ClockObserved, "missing_fields": missing}
}
