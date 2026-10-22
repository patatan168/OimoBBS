// 受理操作と結び付かないHTTP観測を、解決済み板の明示範囲だけで照合する。
package evidence

import (
	"oimobbs/internal/domain"
	"time"
)

// optionalQueryMatches は板/日時/期限を共通検査し、受理操作あり/なしを明示して分離する。
func optionalQueryMatches(r OptionalRecord, scope OptionalQueryScope, ops map[domain.ID]bool, unbound bool, at domain.Time) bool {
	if r.Board == nil || *r.Board != scope.Board || r.Received < scope.From || r.Received >= scope.To || r.Until <= at {
		return false
	}
	if unbound {
		return r.Operation == nil && r.Outcome != "accepted" && r.Outcome != "duplicate"
	}
	return r.Operation != nil && ops[*r.Operation]
}

// ProjectUnbound は結果/出所を基本列にし、IP/ポート/UAを明示選択時だけ投影する。
// 観測上の結果を、投稿未受理の原本証明や閲覧者の本人確認へ読み替えない。
func (r OptionalEvidence) ProjectUnbound(connection bool) map[string]any {
	v := map[string]any{"record_id": r.Record.ID, "board_id": r.Record.Board, "received_at_ns": r.Record.Received, "finished_at_ns": r.Record.Finished, "retention_until_ns": r.Record.Until, "source_event_sha256": r.SourceSHA, "record_kind": "http_observation", "kind": r.Record.Kind, "route": r.Record.Route, "outcome": r.Record.Outcome, "http_status": r.Record.Status, "completeness": "partial_observation", "preservation": "ordinary_retention"}
	v["written_bytes"] = r.Record.Bytes
	v["write_failed"] = r.Record.WriteFailed
	v["request_canceled"] = r.Record.Canceled
	v["finish_stage"] = r.Record.FinishStage
	v["monotonic_elapsed_ns"] = r.Record.Elapsed
	v["missing_fields"] = []MissingField{}
	if r.Record.Status == 0 {
		v["http_status"] = nil
		v["missing_fields"] = []MissingField{{Field: "http_status", Reason: "not_observed"}}
	}
	received := time.Unix(0, int64(r.Record.Received))
	finished := time.Unix(0, int64(r.Record.Finished))
	v["received_at_utc"] = received.UTC().Format(time.RFC3339Nano)
	v["received_at_jst"] = received.In(domain.JST).Format(time.RFC3339Nano)
	v["finished_at_utc"] = finished.UTC().Format(time.RFC3339Nano)
	v["finished_at_jst"] = finished.In(domain.JST).Format(time.RFC3339Nano)
	if connection {
		v["connection"] = map[string]any{"peer": r.Record.Peer, "local": r.Record.Local, "http_version": r.Record.HTTPVersion, "tls_version": r.Record.TLSVersion, "tls_cipher_suite": r.Record.TLSCipher, "user_agent": r.Record.UserAgent, "user_agent_capture_status": r.Record.UAStatus}
	}
	return v
}
