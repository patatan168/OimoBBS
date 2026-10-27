// 操作なしHTTPの保全ZIPが応答失敗と未観測statusを保持することを検査する。
package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"testing"
	"time"
)

func TestUnboundHTTPResponseFailureExport(t *testing.T) {
	s, key, c, actor, now, site, entry := unboundHTTPFixture(t)
	var payload evidence.OptionalPayload
	if e := json.Unmarshal(entry.Payload, &payload); e != nil {
		t.Fatal(e)
	}
	payload.Record.Status, payload.Record.Outcome = 0, "interrupted"
	payload.Record.WriteFailed, payload.Record.Canceled, payload.Record.Bytes = true, true, 17
	payload.Record.Finished, payload.Record.Elapsed = payload.Record.Received-1, 987654321
	raw, e := json.Marshal(payload)
	if e != nil {
		t.Fatal(e)
	}
	event, e := evidence.Seal(evidence.Source{Owner: payload.Owner, Subkey: uint64(payload.Day), Seq: uint64(payload.Seq)}, payload.Record.ID, payload.Record.Kind, raw, domain.Hash{}, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.HoldUnboundHTTP(c.ID, actor, c.ETag(), "failed-http-hold", "保全", site, []evidence.Entry{{Event: event, Payload: raw}}, now)
	if e != nil {
		t.Fatal(e)
	}
	c, export, e := s.Generate(c.ID, actor, c.ETag(), "failed-http-export", "提出", nil, now)
	if e != nil {
		t.Fatal(e)
	}
	zip, e := readArtifact(s.exportPath(c.ID, export.ID))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyZIP(bytes.NewReader(zip), int64(len(zip)), key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal(e)
	}
	assertExportedHTTPFailure(t, zipRecords(t, zip))
}

func assertExportedHTTPFailure(t *testing.T, raw []byte) {
	t.Helper()
	var row struct {
		Outcome  string                  `json:"outcome"`
		Status   *int                    `json:"http_status"`
		Failed   bool                    `json:"write_failed"`
		Canceled bool                    `json:"request_canceled"`
		Bytes    domain.U64              `json:"written_bytes"`
		Stage    string                  `json:"finish_stage"`
		Elapsed  domain.U64              `json:"monotonic_elapsed_ns"`
		Received string                  `json:"received_at_jst"`
		Finished string                  `json:"finished_at_jst"`
		Missing  []evidence.MissingField `json:"missing_fields"`
	}
	if e := json.Unmarshal(raw, &row); e != nil {
		t.Fatal(e)
	}
	if row.Outcome != "interrupted" || row.Status != nil || row.Failed || row.Canceled || row.Bytes != 0 || row.Stage != "" || row.Elapsed != 0 {
		t.Fatal("failure evidence omitted", string(raw))
	}
	received, e := time.Parse(time.RFC3339Nano, row.Received)
	if e != nil {
		t.Fatal(e)
	}
	finished, e := time.Parse(time.RFC3339Nano, row.Finished)
	if e != nil {
		t.Fatal(e)
	}
	if finished.UnixNano() != received.UnixNano()-1 {
		t.Fatal("stored wall clock changed", received, finished)
	}
	if len(row.Missing) != 1 || row.Missing[0].Reason != "not_observed" {
		t.Fatal("unknown status not explained")
	}
	if bytes.Contains(raw, []byte(`"connection"`)) {
		t.Fatal("unselected connection disclosed")
	}
}
