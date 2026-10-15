// JSTの日付境界・配列内日時・重複除去と、異なる観測を消さないことを検査する。
package disclosure

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

func TestExportCSVJSTAndDeduplication(t *testing.T) {
	at := domain.Time(time.Date(2026, 10, 11, 15, 1, 2, 123456789, time.UTC).UnixNano())
	row := map[string]any{"record_id": "sample", "committed_at_ns": at, "committed_at_utc": "2026-10-11T15:01:02.123456789Z", "committed_at_jst": "2026-10-12T00:01:02.123456789+09:00", "identity": map[string]any{"record_id": "sample", "request_id": "request-1"}, "time": map[string]any{"committed_at_ns": at, "received_at_ns": at, "monotonic_elapsed_ns": domain.U64(123)}, "connection": map[string]any{"request_id": "request-1", "received_at_ns": at, "monotonic_elapsed_ns": domain.U64(456)}, "optional_http": []any{map[string]any{"received_at_ns": at, "finished_at_ns": nil, "missing_fields": []any{map[string]any{"field": "finished_at_ns", "reason": "not_observed"}}}}}
	table, e := prepareExportCSV([]map[string]any{row})
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range table.headers {
		if strings.HasSuffix(key, "_at_ns") || strings.HasSuffix(key, "_utc") || key == "identity.record_id" || key == "time.committed_at_jst" || key == "connection.request_id" || key == "connection.received_at_jst" {
			t.Fatal("redundant column", key)
		}
	}
	flat := table.rows[0]
	if flat["committed_at_jst"] != "2026-10-12T00:01:02.123456789+09:00" || flat["time.received_at_jst"] != flat["committed_at_jst"] {
		t.Fatal("JST precision or date boundary", flat)
	}
	if flat["time.monotonic_elapsed_ns"] == nil || flat["connection.monotonic_elapsed_ns"] == nil {
		t.Fatal("different observations lost")
	}
	var out bytes.Buffer
	if e = table.write(&out); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "finished_at_ns") || !strings.Contains(out.String(), "finished_at_jst") {
		t.Fatal("nested timestamp or missing reason not normalized")
	}
	if _, exists := row["committed_at_ns"]; !exists {
		t.Fatal("source projection mutated")
	}
}

func TestSampleZIPUsesSubmissionFormat(t *testing.T) {
	raw, e := SampleZIP()
	if e != nil {
		t.Fatal(e)
	}
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	if len(z.File) != 2 {
		t.Fatal("sample must not imply signed evidence")
	}
	rows := csvZIPTestJSON(t, z)
	if !bytes.Contains(rows, []byte("2026-10-12T00:01:02.123456789+09:00")) || bytes.Contains(rows, []byte("_utc")) {
		t.Fatal("sample timestamps", string(rows))
	}
}
