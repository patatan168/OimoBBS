// 管理HTTP照会が元要求と一致する終了記録を結果へ対応付けることを検査する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"testing"
)

func bindAcceptedResponseFixture(t *testing.T, record *evidence.OptionalRecord, accepted app.AcceptedEvidence) {
	t.Helper()
	selected, e := accepted.Project([]string{"connection"})
	if e != nil {
		t.Fatal(e)
	}
	obs := selected["connection"].(*evidence.HTTPObservation)
	record.Site, record.Boot, record.Connection, record.Request = obs.SiteID, obs.BootID, obs.ConnectionID, obs.RequestID
	record.Received = obs.Received
	record.Finished = max(obs.BodyCompleted, accepted.Committed) + 100
	record.Until = record.Received + domain.Time(evidence.OptionalRetention)
}

func assertAcceptedResponseQuery(t *testing.T, body string, record evidence.OptionalRecord) {
	t.Helper()
	var response struct {
		Result []struct {
			Identity struct {
				Request *domain.ID `json:"request_id"`
			} `json:"identity"`
			Time struct {
				Finished *domain.Time `json:"response_finished_at_ns"`
			} `json:"time"`
			Result struct {
				Ref      *domain.ID `json:"response_event_ref"`
				Response struct {
					Stage string `json:"finish_stage"`
				} `json:"response"`
			} `json:"result"`
		} `json:"result"`
	}
	if e := json.Unmarshal([]byte(body), &response); e != nil {
		t.Fatal(e)
	}
	if len(response.Result) != 1 {
		t.Fatal("response rows")
	}
	result := response.Result[0].Result
	if result.Ref == nil || *result.Ref != record.ID || result.Response.Stage != "handler_return" {
		t.Fatal("accepted response not bound", body)
	}
	identity := response.Result[0].Identity
	if identity.Request == nil || *identity.Request != record.Request {
		t.Fatal("request identity omitted", body)
	}
	timing := response.Result[0].Time
	if timing.Finished == nil || *timing.Finished != record.Finished {
		t.Fatal("response time omitted", body)
	}
	assertAcceptedClientRequestQuery(t, body)
}
