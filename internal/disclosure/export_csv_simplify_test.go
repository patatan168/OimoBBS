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
	row := map[string]any{"record_id": "sample", "committed_at_ns": at, "committed_at_utc": "2026-10-11T15:01:02.123456789Z", "committed_at_jst": "2026-10-12T00:01:02.123456789+09:00", "identity": map[string]any{"record_id": "sample", "request_id": "request-1"}, "time": map[string]any{"committed_at_ns": at, "received_at_ns": at, "monotonic_elapsed_ns": domain.U64(123)}, "connection": map[string]any{"request_id": "request-1", "received_at_ns": at, "monotonic_elapsed_ns": domain.U64(456)}, "optional_http": []any{map[string]any{"record": map[string]any{"received_at_ns": at, "finished_at_ns": nil}}}}
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
	if flat["time.monotonic_elapsed_ns"] != nil || flat["connection.monotonic_elapsed_ns"] != nil {
		t.Fatal("internal timing exported")
	}
	var out bytes.Buffer
	if e = table.write(&out); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "finished_at_ns") || strings.Contains(out.String(), "optional_http") {
		t.Fatal("unselected HTTP array exported")
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
	assertSubmissionReadme(t, raw)
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	if len(z.File) != 2 {
		t.Fatal("sample must not imply signed evidence")
	}
	rows := csvZIPTestJSON(t, z)
	if !bytes.Contains(rows, []byte(`"body":"これは提出形式を確認する架空の投稿です。"`)) {
		t.Fatal("public post sample missing", string(rows))
	}
	if !bytes.Contains(rows, []byte("2026-10-12T00:01:02.123456789+09:00")) || bytes.Contains(rows, []byte("_utc")) {
		t.Fatal("sample timestamps", string(rows))
	}
	if !bytes.Contains(rows, []byte("poster.example.invalid")) || !bytes.Contains(rows, []byte("observed_at_jst")) {
		t.Fatal("DNS sample missing")
	}
	if !bytes.Contains(rows, []byte(`"cookie":{"id":"0100000000000000000000000000000000000000000000000000000000000000","status":"valid"}`)) || bytes.Contains(rows, []byte(`"operation_id"`)) {
		t.Fatal("Cookie identifier or internal identifier projection", string(rows))
	}
}

// TestExportRemovesEmptyGroupsAfterDeduplication は空列だけを除き、対象・異なる観測値・欠測を保持する。
func TestExportRemovesEmptyGroupsAfterDeduplication(t *testing.T) {
	rows := []map[string]any{
		{"thread_key": "123", "attempt_result": "accepted", "received_at_ns": "1800000000000000000", "identity": map[string]any{"thread_key": "123"}, "result": map[string]any{"attempt_result": "accepted"}, "time": map[string]any{"received_at_ns": "1800000000000000000"}, "connection": nil},
		{"thread_key": "123", "received_at_ns": "1800000000000000000", "time": map[string]any{"received_at_ns": "1800000001000000000"}, "content": map[string]any{"public_posts": []any{}}},
	}
	selected, err := SubmissionRecords(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"identity", "result", "time"} {
		if _, ok := selected[0][group]; ok {
			t.Fatal("empty group retained", group)
		}
	}
	if selected[0]["thread_key"] != "123" || selected[0]["attempt_result"] != "accepted" || selected[0]["received_at_jst"] == nil {
		t.Fatal("record values lost")
	}
	if value, ok := selected[0]["connection"]; !ok || value != nil {
		t.Fatal("null missing marker lost")
	}
	if submissionObject(selected[1]["time"])["received_at_jst"] == selected[1]["received_at_jst"] {
		t.Fatal("distinct observation lost")
	}
	if _, ok := submissionObject(rows[0]["identity"])["thread_key"]; !ok {
		t.Fatal("source changed")
	}
	table, err := prepareExportCSV(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range table.headers {
		if key == "identity" || key == "time" || key == "result" {
			t.Fatal("empty CSV group column", key)
		}
	}
	if table.rows[0]["thread_key"] != "123" || table.rows[1]["time.received_at_jst"] == table.rows[1]["received_at_jst"] {
		t.Fatal("CSV target values lost")
	}
}
