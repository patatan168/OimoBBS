// 提出記録の内部IDを除き、処理環境・未知の応答情報を追加しないことを確認する。
package disclosure

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"testing"
)

func assertExportedAcceptedMetadata(t *testing.T, raw []byte, record app.AcceptedEvidence) {
	t.Helper()
	var row struct {
		Operation domain.ID `json:"operation_id"`
		Result    struct {
			Outcome   string    `json:"attempt_result"`
			Operation domain.ID `json:"accepted_operation_id"`
		} `json:"result"`
	}
	if e := json.Unmarshal(raw, &row); e != nil {
		t.Fatal(e)
	}
	if row.Operation != (domain.ID{}) || row.Result.Operation != (domain.ID{}) || row.Result.Outcome != "accepted" {
		t.Fatal("internal identifiers exported or result lost", string(raw))
	}
	for _, key := range []string{`"environment"`, `"text_codec_version"`, `"planned_http_status"`} {
		if bytes.Contains(raw, []byte(key)) {
			t.Fatal("internal field exported", key)
		}
	}
}
