// 受理要求と同一の観測IDを持つHTTP終了記録だけを提出結果へ対応付ける。
package app

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// AttachAcceptedHTTPResponse はconnection選択後の同一要求の事後記録を結果へ付加する。
// 操作IDだけが同じ再送を採用せず、複数一致なら参照を確定しない。
// 記録はhandler終了の観測であり、相手先受領や通信完了の証明ではない。
func AttachAcceptedHTTPResponse(row map[string]any) {
	obs, ok := row["connection"].(*evidence.HTTPObservation)
	if !ok || obs == nil {
		return
	}
	result, ok := row["result"].(map[string]any)
	if !ok {
		return
	}
	operation, ok := row["operation_id"].(domain.ID)
	if !ok {
		return
	}
	logs, _ := row["optional_http"].([]evidence.OptionalEvidence)
	matches := []evidence.OptionalEvidence{}
	for _, log := range logs {
		if sameAcceptedHTTPRequest(obs, operation, log.Record) {
			matches = append(matches, log)
		}
	}
	if len(matches) == 0 {
		return
	}
	if len(matches) > 1 {
		setResponseMissingReason(result, "multiple_matching_http_records")
		attachResponseTime(row, nil, "multiple_matching_http_records")
		return
	}
	log := matches[0]
	result["response_event_ref"] = log.Record.ID
	result["response"] = projectedHTTPResponse(log)
	setResponseMissingReason(result, "")
	attachResponseTime(row, &log.Record.Finished, "")
}

// attachResponseTime は照合済みhandler終了時刻だけを受付時計と並べ、経過値を置換しない。
func attachResponseTime(row map[string]any, finished *domain.Time, reason string) {
	timing, ok := row["time"].(map[string]any)
	if !ok {
		return
	}
	timing["response_finished_at_ns"] = finished
	fields, _ := timing["missing_fields"].([]evidence.MissingField)
	next := []evidence.MissingField{}
	for _, field := range fields {
		if field.Field != "response_finished_at_ns" {
			next = append(next, field)
		}
	}
	if reason != "" {
		next = append(next, evidence.MissingField{Field: "response_finished_at_ns", Reason: reason})
	}
	timing["missing_fields"] = next
}

// sameAcceptedHTTPRequest は保存時のサイト/板/起動/接続/要求/操作をすべて照合する。
func sameAcceptedHTTPRequest(obs *evidence.HTTPObservation, operation domain.ID, record evidence.OptionalRecord) bool {
	if record.Board == nil || record.Operation == nil {
		return false
	}
	return record.Kind == "response" && record.Site == obs.SiteID && *record.Board == obs.BoardID && record.Boot == obs.BootID && record.Connection == obs.ConnectionID && record.Request == obs.RequestID && *record.Operation == operation
}

// projectedHTTPResponse は応答の観測値だけを取り出し、予定statusと区別する。
func projectedHTTPResponse(log evidence.OptionalEvidence) map[string]any {
	r := log.Record
	var status *int
	missing := []evidence.MissingField{}
	if r.Status != 0 {
		status = &r.Status
	} else {
		missing = append(missing, evidence.MissingField{Field: "http_status", Reason: "not_observed"})
	}
	return map[string]any{"record_id": r.ID, "source_event_sha256": log.SourceSHA, "finished_at_ns": r.Finished, "monotonic_elapsed_ns": r.Elapsed, "finish_stage": r.FinishStage, "outcome": r.Outcome, "http_status": status, "written_bytes": r.Bytes, "write_failed": r.WriteFailed, "request_canceled": r.Canceled, "missing_fields": missing}
}

// setResponseMissingReason は事後参照の欠測だけを更新し、予定statusの不明を維持する。
func setResponseMissingReason(result map[string]any, reason string) {
	fields, _ := result["missing_fields"].([]evidence.MissingField)
	next := []evidence.MissingField{}
	for _, field := range fields {
		if field.Field != "response_event_ref" {
			next = append(next, field)
		}
	}
	if reason != "" {
		result["response_event_ref"] = nil
		delete(result, "response")
		next = append(next, evidence.MissingField{Field: "response_event_ref", Reason: reason})
	}
	result["missing_fields"] = next
}
