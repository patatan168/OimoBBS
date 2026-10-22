// 管理HTTP照会が元要求と一致する終了記録を結果へ対応付けることを検査する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"testing"
	"time"
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
				Finished string `json:"response_finished_at_jst"`
			} `json:"time"`
			Status int `json:"response_http_status"`
		} `json:"result"`
	}
	if e := json.Unmarshal([]byte(body), &response); e != nil {
		t.Fatal(e)
	}
	if len(response.Result) != 1 {
		t.Fatal("response rows")
	}
	if response.Result[0].Status != record.Status {
		t.Fatal("accepted response not bound", body)
	}
	identity := response.Result[0].Identity
	if identity.Request != nil {
		t.Fatal("internal request identity exported", body)
	}
	timing := response.Result[0].Time
	if timing.Finished != time.Unix(0, int64(record.Finished)).In(domain.JST).Format(time.RFC3339Nano) {
		t.Fatal("response time omitted", body)
	}
	assertAcceptedClientRequestQuery(t, body)
}
