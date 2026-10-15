// 署名ZIPの受理結果が保全したdecisionに対応し、応答の不明値を保持することを検査する。
package disclosure

import (
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"slices"
	"testing"
	"time"
)

func assertExportedAcceptedMetadata(t *testing.T, raw []byte, record app.AcceptedEvidence) {
	t.Helper()
	var row struct {
		Result struct {
			Outcome   string                  `json:"attempt_result"`
			Operation domain.ID               `json:"accepted_operation_id"`
			Decided   string                  `json:"decision_at_jst"`
			Status    *int                    `json:"planned_http_status"`
			Response  *domain.ID              `json:"response_event_ref"`
			Missing   []evidence.MissingField `json:"missing_fields"`
		} `json:"result"`
		Environment struct {
			Schema  string                  `json:"evidence_schema"`
			Codec   *string                 `json:"text_codec_version"`
			Missing []evidence.MissingField `json:"missing_fields"`
		} `json:"environment"`
	}
	if e := json.Unmarshal(raw, &row); e != nil {
		t.Fatal(e)
	}
	if row.Result.Outcome != "accepted" || row.Result.Operation != record.Operation || row.Result.Decided != time.Unix(0, int64(record.Committed)).In(domain.JST).Format(time.RFC3339Nano) {
		t.Fatal("saved decision not exported", string(raw))
	}
	if row.Result.Status != nil || row.Result.Response != nil {
		t.Fatal("unrecorded HTTP response inferred")
	}
	if row.Environment.Schema != "fixture" || row.Environment.Codec != nil {
		t.Fatal("unrecorded environment inferred", string(raw))
	}
	if !slices.Equal([]int{len(row.Result.Missing), len(row.Environment.Missing)}, []int{2, 5}) {
		t.Fatal("unknown values have no reasons")
	}
}
