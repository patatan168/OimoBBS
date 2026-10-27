// 操作の再送と元要求のHTTP終了を区別し、曖昧な事後参照を確定しないことを検査する。
package app

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"testing"
)

func responseProjectionFixture(t *testing.T) (map[string]any, evidence.OptionalEvidence) {
	t.Helper()
	r, _ := acceptedContentFixture(t)
	row, e := r.Project(nil)
	if e != nil {
		t.Fatal(e)
	}
	obs := &evidence.HTTPObservation{SiteID: domain.NewID(), BoardID: r.Board, BootID: domain.NewID(), ConnectionID: domain.NewID(), RequestID: domain.NewID(), MonotonicElapsed: 80}
	row["connection"] = obs
	row["time"] = acceptedRequestTime(r.Committed, obs, row["result"].(map[string]any))
	log := evidence.OptionalEvidence{Record: evidence.OptionalRecord{ID: domain.NewID(), Site: obs.SiteID, Board: &obs.BoardID, Operation: &r.Operation, Boot: obs.BootID, Connection: obs.ConnectionID, Request: obs.RequestID, Kind: "response", Outcome: "interrupted", Status: 200, Finished: r.Committed + 20, FinishStage: "handler_return", WriteFailed: true, Canceled: true}}
	row["optional_http"] = []evidence.OptionalEvidence{log}
	return row, log
}

func TestAcceptedHTTPResponseMatchesOriginalRequest(t *testing.T) {
	row, log := responseProjectionFixture(t)
	AttachAcceptedHTTPResponse(row)
	result := row["result"].(map[string]any)
	if result["response_event_ref"] != log.Record.ID || result["planned_http_status"] != nil {
		t.Fatal("observed response substituted for planned status", result)
	}
	response := result["response"].(map[string]any)
	if response["finished_at_ns"] != log.Record.Finished || response["write_failed"] != true || response["request_canceled"] != true || response["finish_stage"] != "handler_return" {
		t.Fatal("failed/interrupted response reported as delivered", response)
	}
	timing := row["time"].(map[string]any)
	if *timing["response_finished_at_ns"].(*domain.Time) != log.Record.Finished || timing["monotonic_elapsed_ns"] != domain.U64(80) {
		t.Fatal("handler finish replaced capture elapsed")
	}
}

func TestAcceptedHTTPResponseRejectsDifferentObservation(t *testing.T) {
	for _, field := range []string{"site", "board", "boot", "connection", "request", "operation", "kind"} {
		t.Run(field, func(t *testing.T) {
			row, log := responseProjectionFixture(t)
			changed := domain.NewID()
			switch field {
			case "site":
				log.Record.Site = changed
			case "board":
				log.Record.Board = &changed
			case "boot":
				log.Record.Boot = changed
			case "connection":
				log.Record.Connection = changed
			case "request":
				log.Record.Request = changed
			case "operation":
				log.Record.Operation = &changed
			case "kind":
				log.Record.Kind = "attempt"
			}
			row["optional_http"] = []evidence.OptionalEvidence{log}
			AttachAcceptedHTTPResponse(row)
			if row["result"].(map[string]any)["response_event_ref"] != nil {
				t.Fatal("different observation adopted", field)
			}
		})
	}
}

func TestAcceptedHTTPResponseDoesNotResolveAmbiguity(t *testing.T) {
	row, log := responseProjectionFixture(t)
	other := log
	other.Record.ID = domain.NewID()
	row["optional_http"] = []evidence.OptionalEvidence{log, other}
	AttachAcceptedHTTPResponse(row)
	result := row["result"].(map[string]any)
	if result["response_event_ref"] != nil {
		t.Fatal("arbitrary response chosen")
	}
	missing := result["missing_fields"].([]evidence.MissingField)
	if missing[len(missing)-1].Reason != "multiple_matching_http_records" {
		t.Fatal("ambiguous response not explained")
	}
}

func TestAcceptedHTTPResponseRequiresConnectionSelection(t *testing.T) {
	row, _ := responseProjectionFixture(t)
	delete(row, "connection")
	AttachAcceptedHTTPResponse(row)
	result := row["result"].(map[string]any)
	if result["response_event_ref"] != nil {
		t.Fatal("unselected response referenced")
	}
	if _, found := result["response"]; found {
		t.Fatal("unselected response disclosed")
	}
}

func TestAcceptedHTTPResponseUnknownStatus(t *testing.T) {
	row, log := responseProjectionFixture(t)
	log.Record.Status = 0
	row["optional_http"] = []evidence.OptionalEvidence{log}
	AttachAcceptedHTTPResponse(row)
	response := row["result"].(map[string]any)["response"].(map[string]any)
	if response["http_status"].(*int) != nil || len(response["missing_fields"].([]evidence.MissingField)) != 1 {
		t.Fatal("unknown response status inferred")
	}
}
