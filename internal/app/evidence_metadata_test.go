// 受理結果の原本対応と、保存時の環境情報・取得不能理由を検査する。
package app

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"testing"
)

func TestAcceptedMetadataUsesStoredDecision(t *testing.T) {
	r, _ := acceptedContentFixture(t)
	var d postingDecision
	if e := json.Unmarshal(r.Decision.Payload, &d); e != nil {
		t.Fatal(e)
	}
	d.Recovered = true
	d.Decided += 100
	r.Decision.Payload, _ = json.Marshal(d)
	out, e := r.Project(nil)
	if e != nil {
		t.Fatal(e)
	}
	result := out["result"].(map[string]any)
	if result["attempt_result"] != "accepted" || result["accepted_operation_id"] != r.Operation || result["thread_seq"] != d.ThreadSeq || result["thread_frame_sha256"] != d.FrameSHA || result["decision_at_ns"] != d.Decided || result["recovered"] != true {
		t.Fatal("saved decision not projected", result)
	}
	assertUnknownAcceptedResponse(t, result)
	raw, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	assertMetadataPrivacy(t, raw)
}

func assertUnknownAcceptedResponse(t *testing.T, result map[string]any) {
	t.Helper()
	if result["planned_http_status"] != nil || result["response_event_ref"] != nil {
		t.Fatal("HTTP response inferred from acceptance")
	}
	missing := result["missing_fields"].([]evidence.MissingField)
	if len(missing) != 2 || missing[0].Reason == "" || missing[1].Reason == "" {
		t.Fatal("unknown HTTP fields have no reason")
	}
}

func assertMetadataPrivacy(t *testing.T, raw []byte) {
	t.Helper()
	for _, secret := range []string{`"content"`, `"connection"`, `"principal"`, `"private"`, `"source_ip"`, `"rate_keys"`, "SECRET_CREDENTIAL", "prepared_frame_base64"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("unselected data in metadata", secret)
		}
	}
}

func TestAcceptedMetadataRejectsUnrelatedDecision(t *testing.T) {
	for _, changed := range []string{"operation", "proposal", "outcome", "frame"} {
		t.Run(changed, func(t *testing.T) {
			r, _ := acceptedContentFixture(t)
			var d postingDecision
			if e := json.Unmarshal(r.Decision.Payload, &d); e != nil {
				t.Fatal(e)
			}
			switch changed {
			case "operation":
				d.OperationID = domain.NewID()
			case "proposal":
				d.ProposalID = domain.NewID()
			case "outcome":
				d.Outcome = "not_accepted"
			case "frame":
				d.FrameSHA[0] ^= 1
			}
			r.Decision.Payload, _ = json.Marshal(d)
			if _, e := r.Project(nil); e != ErrEvidenceGap {
				t.Fatal("unrelated decision accepted", e)
			}
		})
	}
}

func TestAcceptedEnvironmentUsesSavedValues(t *testing.T) {
	revision := domain.U64(42)
	obs := &evidence.HTTPObservation{ServerBuildID: "saved-build", ProxyConfigRevision: &revision}
	out, e := projectAcceptedEnvironment(json.RawMessage(`{"schema":"form-post-v4","text_codec_version":"sjis-compat-v1","renderer_profile":"dat-cap-v2","credential":"SECRET_CREDENTIAL"}`), obs)
	if e != nil {
		t.Fatal(e)
	}
	for key, value := range map[string]string{"server_build_id": "saved-build", "text_codec_version": "sjis-compat-v1", "renderer_profile": "dat-cap-v2", "evidence_schema": "form-post-v4"} {
		if *out[key].(*string) != value {
			t.Fatal("saved value replaced", key)
		}
	}
	if *out["proxy_policy_revision"].(*domain.U64) != revision || out["clock_policy_revision"] != nil {
		t.Fatal("policy revisions inferred or omitted")
	}
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte("SECRET_CREDENTIAL")) {
		t.Fatal("unknown capture field disclosed")
	}
}

func TestAcceptedEnvironmentMissingValuesHaveReasons(t *testing.T) {
	out, e := projectAcceptedEnvironment(json.RawMessage(`{}`), nil)
	if e != nil {
		t.Fatal(e)
	}
	missing := out["missing_fields"].([]evidence.MissingField)
	if len(missing) != 6 {
		t.Fatal("missing environmental value not explained", missing)
	}
	raw, _ := json.Marshal(out)
	var decoded map[string]any
	if e = json.Unmarshal(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	for _, field := range missing {
		if decoded[field.Field] != nil || field.Reason == "" {
			t.Fatal("missing value invented", field)
		}
	}
}

func TestAcceptedEnvironmentPreservesProxyMissingReason(t *testing.T) {
	obs := &evidence.HTTPObservation{ServerBuildID: "saved-build", MissingFields: []evidence.MissingField{{Field: "proxy_config_revision", Reason: "direct_connection"}}}
	out, e := projectAcceptedEnvironment(json.RawMessage(`{}`), obs)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range out["missing_fields"].([]evidence.MissingField) {
		if field.Field == "proxy_policy_revision" {
			if field.Reason != "direct_connection" {
				t.Fatal("recorded missing reason replaced", field)
			}
			return
		}
	}
	t.Fatal("missing proxy revision has no reason")
}
