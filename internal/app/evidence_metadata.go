// 受理原本から結果と保存時の環境を投影し、未記録の応答情報を明示する。
package app

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/strictjson"
)

// projectAcceptedResult はproposalに対応する受理decisionの記録値を返す。
// 確定はHTTP応答完了を意味しないため、応答情報を推定しない。
func projectAcceptedResult(r AcceptedEvidence, p postingProposal) (map[string]any, error) {
	var d postingDecision
	if e := strictjson.Decode(r.Decision.Payload, &d); e != nil {
		return nil, e
	}
	if d.Outcome != "accepted" || !d.matches(p, r.Proposal.Event) {
		return nil, ErrEvidenceGap
	}
	return map[string]any{
		"attempt_result":        d.Outcome,
		"accepted_operation_id": d.OperationID,
		"thread_seq":            d.ThreadSeq,
		"thread_frame_sha256":   d.FrameSHA,
		"decision_at_ns":        d.Decided,
		"recovered":             d.Recovered,
		"planned_http_status":   nil,
		"response_event_ref":    nil,
		"completeness":          "partial",
		"retention_until_ns":    d.Retention,
		"missing_fields": []evidence.MissingField{
			{Field: "planned_http_status", Reason: "not_recorded_in_posting_decision"},
			{Field: "response_event_ref", Reason: "requires_separate_http_record"},
		},
	}, nil
}

// projectAcceptedEnvironment は秘密のない許可項目だけを保存時のcaptureから返す。
// 現在のbuildや設定へ置換せず、未保存項目はnullと理由を返す。
func projectAcceptedEnvironment(raw json.RawMessage, obs *evidence.HTTPObservation) (map[string]any, error) {
	var saved struct {
		Schema   *string `json:"schema"`
		Codec    *string `json:"text_codec_version"`
		Renderer *string `json:"renderer_profile"`
	}
	if e := json.Unmarshal(raw, &saved); e != nil {
		return nil, e
	}
	var build *string
	var proxyRevision *domain.U64
	if obs != nil {
		build = &obs.ServerBuildID
		proxyRevision = obs.ProxyConfigRevision
	}
	fields := map[string]*string{"server_build_id": build, "text_codec_version": saved.Codec, "renderer_profile": saved.Renderer, "evidence_schema": saved.Schema}
	missing := []evidence.MissingField{
		{Field: "clock_policy_revision", Reason: "not_recorded_in_capture"},
	}
	if proxyRevision == nil {
		reason := "not_recorded_in_capture"
		if obs != nil {
			for _, field := range obs.MissingFields {
				if field.Field == "proxy_config_revision" {
					reason = field.Reason
				}
			}
		}
		missing = append(missing, evidence.MissingField{Field: "proxy_policy_revision", Reason: reason})
	}
	out := map[string]any{"clock_policy_revision": nil, "proxy_policy_revision": proxyRevision}
	for _, key := range []string{"server_build_id", "text_codec_version", "renderer_profile", "evidence_schema"} {
		value := fields[key]
		if value == nil {
			missing = append(missing, evidence.MissingField{Field: key, Reason: "not_recorded_in_capture"})
		}
		out[key] = value
	}
	out["missing_fields"] = missing
	return out, nil
}
