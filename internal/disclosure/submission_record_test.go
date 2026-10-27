// 提出物と照会の許可項目を固定し、内部情報・文字コード・未選択情報の混入を防ぐ。
package disclosure

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// assertSubmissionReadme は実際の提出ZIPの全CSV列とREADMEの説明を対応付ける。
func assertSubmissionReadme(t *testing.T, raw []byte) {
	t.Helper()
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	var readme, records []byte
	for _, file := range z.File {
		if file.Name != "readme.txt" && file.Name != "records.csv" {
			continue
		}
		r, e := file.Open()
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
		if file.Name == "readme.txt" {
			readme = body
		} else {
			records = body
		}
	}
	headers, e := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(records, []byte("\xef\xbb\xbf")))).Read()
	if e != nil {
		t.Fatal(e)
	}
	for _, header := range headers {
		if !strings.Contains(string(readme), "- "+header+" [") {
			t.Fatal("README missing column", header)
		}
	}
	for _, removed := range []string{"declared_charset", "text_codec_version", "dat_base64", "selected_headers", "reported_headers", "monotonic_elapsed_ns", "policy_versions", "operation_id", "request_id", "connection_id", "record_id", "board_id", "proxy_profile_id"} {
		if bytes.Contains(readme, []byte("- "+removed+" [")) || bytes.Contains(records, []byte(removed)) {
			t.Fatal("obsolete field or explanation", removed)
		}
	}
	if !bytes.Contains(readme, []byte("Cookie由来のID")) {
		t.Fatal("Cookie identifier explanation missing")
	}
	for _, obsolete := range []string{"旧仕様", "従来", "以前の仕様", "削除しました", "内部ID", "重複列"} {
		if bytes.Contains(readme, []byte(obsolete)) {
			t.Fatal("README refers to obsolete specification", obsolete)
		}
	}
}

func TestSubmissionRecordsExcludeInternalFields(t *testing.T) {
	row := map[string]any{
		"record_id": "record", "committed_at_ns": "1800000000000000000", "thread_key": "123", "post_number": 1,
		"environment": map[string]any{"text_codec_version": "INTERNAL", "server_build_id": "INTERNAL"},
		"cookie":      map[string]any{"id": "cookie-1", "status": "valid", "secret": "INTERNAL"},
		"principal":   map[string]any{"credential_hmac": "INTERNAL"}, "operation_id": "operation-1",
		"client":     map[string]any{"resolved_ip": "203.0.113.4", "resolved_port": 54321, "proxy_profile_id": "proxy-1", "reverse_dns": map[string]any{"names": []string{"poster.example"}, "status": "confirmed", "confirmed_name": "poster.example", "observed_at_ns": "1800000000000000000", "resolver": "INTERNAL"}},
		"connection": map[string]any{"schema": "INTERNAL", "peer": map[string]any{"ip": "10.0.0.2", "port": 443}, "tls_cipher_suite": 4865, "selected_headers": []any{map[string]any{"name": "User-Agent", "values": []any{map[string]any{"display": "Browser/1", "base64": "INTERNAL"}}}, map[string]any{"name": "Origin", "values": []any{map[string]any{"display": "INTERNAL"}}}}},
		"request":    map[string]any{"board_alias_used": "news", "canonical_host": "bbs.example", "declared_charset": "INTERNAL", "missing_fields": []any{map[string]any{"field": "declared_charset", "reason": "not_declared"}}},
		"content":    map[string]any{"body": "本文", "dat_base64": "INTERNAL", "body_sha256": "INTERNAL"},
	}
	before, _ := json.Marshal(row)
	rows, err := SubmissionRecords([]map[string]any{row})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rows)
	if bytes.Contains(raw, []byte("INTERNAL")) || bytes.Contains(raw, []byte("10.0.0.2")) || bytes.Contains(raw, []byte("declared_charset")) || bytes.Contains(raw, []byte("operation-1")) || bytes.Contains(raw, []byte("proxy-1")) {
		t.Fatal(string(raw))
	}
	for _, want := range []string{"203.0.113.4", "54321", "poster.example", "Browser/1", "news", "本文", "+09:00", "cookie-1"} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatal("lost submission field", want, string(raw))
		}
	}
	after, _ := json.Marshal(row)
	if !bytes.Equal(before, after) {
		t.Fatal("original mutated")
	}
	table, err := prepareExportCSV([]map[string]any{row})
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range table.headers {
		if strings.Contains(header, "charset") || strings.HasPrefix(header, "environment") || strings.HasPrefix(header, "principal") || strings.HasSuffix(header, "_id") {
			t.Fatal(header)
		}
	}
	// 許可項目でも未選択の入力から補完しない。
	only, err := SubmissionRecords([]map[string]any{{"record_id": "record", "environment": row["environment"]}})
	if err != nil {
		t.Fatal(err)
	}
	if len(only[0]) != 0 {
		t.Fatal("unselected data added", only)
	}
	if ValidColumns([]string{"principal"}) {
		t.Fatal("removed column accepted")
	}
}

func TestSubmissionPostingTargetUsesSavedValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request map[string]any
	}{
		{"saved alias", map[string]any{"board_alias_used": "old-news", "canonical_host": "bbs.example"}},
		{"missing", map[string]any{"board_alias_used": nil, "missing_fields": []any{map[string]any{"field": "board_alias_used", "reason": "not_recorded_in_capture"}}}},
		{"absent", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := map[string]any{"board_id": "internal-board-id", "thread_key": "1791605101", "post_number": 3, "request": tc.request}
			before, _ := json.Marshal(source)
			rows, err := SubmissionRecords([]map[string]any{source})
			if err != nil {
				t.Fatal(err)
			}
			row := rows[0]
			if row["thread_key"] != "1791605101" || row["post_number"] != json.Number("3") {
				t.Fatal("target changed", row)
			}
			key, exists := row["board_key"]
			want, saved := tc.request["board_alias_used"]
			if exists != saved || key != want {
				t.Fatal("saved board key changed", row)
			}
			if request := submissionObject(row["request"]); request != nil {
				if _, exists := request["board_alias_used"]; exists {
					t.Fatal("duplicate board key")
				}
			}
			if tc.name == "missing" {
				fields, _ := row["missing_fields"].([]any)
				if len(fields) != 1 || submissionObject(fields[0])["field"] != "board_key" || submissionObject(fields[0])["reason"] != "not_recorded_in_capture" {
					t.Fatal("missing reason lost", row)
				}
			}
			after, _ := json.Marshal(source)
			if !bytes.Equal(before, after) {
				t.Fatal("original mutated")
			}
		})
	}
}

func TestSubmissionResponseColumnsExcludeHTTPArray(t *testing.T) {
	source := map[string]any{
		"connection":    map[string]any{"user_agent": "Browser/1"},
		"time":          map[string]any{"response_finished_at_ns": "1800000000000000000"},
		"result":        map[string]any{"attempt_result": "accepted", "response": map[string]any{"source_event_sha256": "matched-source", "finished_at_ns": "1800000000000000000", "http_status": 200, "outcome": "accepted"}},
		"optional_http": []any{map[string]any{"source_event_sha256": "unrelated-source", "record": map[string]any{"kind": "access", "user_agent": "UNRELATED-UA", "peer": map[string]any{"ip": "203.0.113.5"}}}},
	}
	before, _ := json.Marshal(source)
	table, err := prepareExportCSV([]map[string]any{source})
	if err != nil {
		t.Fatal(err)
	}
	row := table.rows[0]
	if row["response_http_status"] != json.Number("200") || row["response_outcome"] != "accepted" || row["response_source_event_sha256"] != "matched-source" || row["time.response_finished_at_jst"] == nil {
		t.Fatal("response columns missing", row)
	}
	if row["connection.user_agent"] != "Browser/1" {
		t.Fatal("request UA lost")
	}
	var out bytes.Buffer
	if err = table.write(&out); err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"optional_http", "UNRELATED-UA", "unrelated-source", "203.0.113.5", "result.response.", "finished_at_ns"} {
		if bytes.Contains(out.Bytes(), []byte(removed)) {
			t.Fatal("unnecessary HTTP data", removed)
		}
	}
	after, _ := json.Marshal(source)
	if !bytes.Equal(before, after) {
		t.Fatal("source mutated")
	}
}

// TestSubmissionExcludesSystemPosts は本文や名前が似ていても種類で本人と自動投稿を区別する。
func TestSubmissionExcludesSystemPosts(t *testing.T) {
	row := map[string]any{"post_number": 7, "identity": map[string]any{"post_numbers": []int{7, 8}}, "content": map[string]any{"body": "終了しました", "public_posts": []any{
		map[string]any{"number": 7, "kind": "user", "name": "終了案内", "body": "終了しました"},
		map[string]any{"number": 8, "kind": "system", "name": "AUTO_NAME", "body": "AUTO_BODY", "identity": map[string]any{"id": "AUTO_ID"}},
	}}}
	before, _ := json.Marshal(row)
	rows, err := SubmissionRecords([]map[string]any{row})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rows)
	if bytes.Contains(raw, []byte("AUTO_")) || bytes.Contains(raw, []byte("post_numbers")) {
		t.Fatal("system post in submission", string(raw))
	}
	posts := submissionObject(rows[0]["content"])["public_posts"].([]any)
	if len(posts) != 1 || submissionObject(posts[0])["body"] != "終了しました" {
		t.Fatal("user's ending-like text removed")
	}
	after, _ := json.Marshal(row)
	if !bytes.Equal(before, after) {
		t.Fatal("source changed")
	}
}
