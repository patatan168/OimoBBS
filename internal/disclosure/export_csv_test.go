// CSVの可読カラム・精度・引用・特殊値と、旧形式の拒否を確認する。
package disclosure

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

func TestExportCSVCellsAndColumnReadme(t *testing.T) {
	rows := []map[string]any{
		{"record_id": "001", "connection": map[string]any{"peer": map[string]any{"ip": "2001:db8::1", "port": 443}}, "content": map[string]any{"body": "日本語,\"引用\"\n次の行", "title": "入力件名", "mail": "非公開メール", "name": "入力名", "public_title": "=1+1", "public_posts": []any{map[string]any{"number": 1, "kind": "user", "name": `\N`, "mail": "", "body": "日本語,\"引用\"\n次の行"}}}, "committed_at_ns": domain.Time(1800000000123456789), "http_status": nil, "missing_fields": []any{map[string]any{"field": "http_status", "reason": "not_observed"}}},
		{"record_id": "002", "content": map[string]any{"body": "'元の引用", "public_title": " +SUM(1,2)"}, "http_status": 200},
	}
	table, e := prepareExportCSV(rows)
	if e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e = table.write(&out); e != nil {
		t.Fatal(e)
	}
	if !bytes.HasPrefix(out.Bytes(), []byte("\xef\xbb\xbf")) {
		t.Fatal("BOM")
	}
	records, e := csv.NewReader(bytes.NewReader(out.Bytes()[3:])).ReadAll()
	if e != nil || len(records) != 3 {
		t.Fatal("CSV rows", e)
	}
	index := map[string]int{}
	for i, key := range records[0] {
		index[key] = i
		if !strings.Contains(string(table.readme()), "- "+key+" [") {
			t.Fatal("column missing from readme", key)
		}
	}
	expected := map[string]string{"connection.peer.ip": "2001:db8::1", "connection.peer.port": "443", "public_body": "日本語,\"引用\"\n次の行", "public_title": "'=1+1", "public_mail": `\E`, "public_name": `'\N`, "committed_at_jst": time.Unix(0, 1800000000123456789).In(domain.JST).Format(time.RFC3339Nano), "http_status": `\N`}
	for key, want := range expected {
		i, exists := index[key]
		if !exists || records[1][i] != want {
			t.Fatal("cell", key, records[1][i], want)
		}
	}
	if records[2][index["committed_at_jst"]] != "" || records[2][index["public_body"]] != "''元の引用" || records[2][index["public_title"]] != "' +SUM(1,2)" {
		t.Fatal("missing or text prefix")
	}
	if count, e := countCSVRecords(out.Bytes()); e != nil || count != 2 {
		t.Fatal("multiline count", count, e)
	}
	for _, meaning := range []string{"直近の接続相手", "投稿者本人の本文", "記録の確定時刻", "欠測項目"} {
		if !strings.Contains(string(table.readme()), meaning) {
			t.Fatal("meaning", meaning)
		}
	}
}

func TestExportCSVCountRejectsMalformedRows(t *testing.T) {
	for _, raw := range []string{"", "a,a\n1,2\n", "a,b\n1\n", "a\n\"unclosed\n"} {
		if _, e := countCSVRecords([]byte(raw)); e == nil {
			t.Fatal("invalid CSV accepted", raw)
		}
	}
	table, e := prepareExportCSV(nil)
	if e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e = table.write(&out); e != nil {
		t.Fatal(e)
	}
	if count, e := countCSVRecords(out.Bytes()); e != nil || count != 0 {
		t.Fatal("empty export", count, e)
	}
}

func TestVerifyZIPRejectsJSONL(t *testing.T) {
	_, key, input, actor, now, _ := fixture(t)
	files := map[string][]byte{"records.jsonl": []byte("{\"record_id\":\"legacy\"}\n"), "readme.txt": []byte("legacy")}
	files["public-keys.json"], _ = json.Marshal(map[string]any{"signing_key_id": 10, "algorithm": "Ed25519", "public_key_base64": base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	m := Manifest{Schema: "evidence-export-v1", ID: domain.NewID(), Case: domain.NewID(), Actor: actor, Generated: now.UTC().Format(time.RFC3339Nano), Until: domain.Time(now.Add(24 * time.Hour).UnixNano()), Scope: input.Scope, Count: 1, Sources: []domain.Hash{}, Missing: []domain.ID{}, Columns: []string{}, KeyID: 10}
	m.Scope.Records = []domain.ID{}
	for _, name := range []string{"records.jsonl", "public-keys.json", "readme.txt"} {
		raw := files[name]
		m.Files = append(m.Files, exportFile{name, domain.U64(len(raw)), sha256.Sum256(raw)})
	}
	files["manifest.json"], _ = json.Marshal(m)
	digest := sha256.Sum256(files["manifest.json"])
	files["manifest.sig"] = ed25519.Sign(key, digest[:])
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, name := range []string{"records.jsonl", "public-keys.json", "readme.txt", "manifest.json", "manifest.sig"} {
		file, e := writer.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = file.Write(files[name]); e != nil {
			t.Fatal(e)
		}
	}
	if e := writer.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyZIP(bytes.NewReader(buf.Bytes()), int64(buf.Len()), key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("JSONL format accepted")
	}
}

// csvTestJSON はCSVとREADMEの型から既存の投影検査用JSONへ戻す。新CSVセル自体は上記で独立検査する。
func csvTestJSON(t *testing.T, raw, readme []byte) []byte {
	t.Helper()
	records, e := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	types := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^- (.+) \[([^]]+)\]:`).FindAllStringSubmatch(string(readme), -1) {
		types[m[1]] = m[2]
	}
	var out bytes.Buffer
	for _, cells := range records[1:] {
		row := map[string]any{}
		for i, cell := range cells {
			if cell == "" {
				continue
			}
			var value any
			switch cell {
			case `\N`:
				value = nil
			case `\E`:
				value = ""
			default:
				if strings.Contains(types[records[0][i]], "string") {
					value = strings.TrimPrefix(cell, "'")
				} else {
					decoder := json.NewDecoder(strings.NewReader(cell))
					decoder.UseNumber()
					if e = decoder.Decode(&value); e != nil {
						t.Fatal(e)
					}
				}
			}
			path := strings.Split(records[0][i], ".")
			node := row
			for _, key := range path[:len(path)-1] {
				if node[key] == nil {
					node[key] = map[string]any{}
				}
				node = node[key].(map[string]any)
			}
			node[path[len(path)-1]] = value
		}
		content := map[string]any{}
		if value, exists := row["public_body"]; exists {
			content["body"] = value
			delete(row, "public_body")
		}

		if value, exists := row["public_title"]; exists {
			content["public_title"] = value
			delete(row, "public_title")
		}
		post := map[string]any{}
		for _, key := range []string{"name", "mail"} {
			if value, exists := row["public_"+key]; exists {
				post[key] = value
				delete(row, "public_"+key)
			}
		}
		identity := map[string]any{}
		for _, key := range []string{"date_text", "id", "slip", "trip", "cap"} {
			if value, exists := row["public_"+key]; exists {
				identity[key] = value
				delete(row, "public_"+key)
			}
		}
		if len(identity) > 0 {
			post["identity"] = identity
		}
		if len(post) > 0 {
			post["number"] = row["post_number"]
			content["public_posts"] = []any{post}
		}
		if len(content) > 0 {
			row["content"] = content
		}
		if e = json.NewEncoder(&out).Encode(row); e != nil {
			t.Fatal(e)
		}
	}
	return out.Bytes()
}

func csvZIPTestJSON(t *testing.T, z *zip.Reader) []byte {
	t.Helper()
	files := map[string][]byte{}
	for _, f := range z.File {
		if f.Name != "records.csv" && f.Name != "readme.txt" {
			continue
		}
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		files[f.Name], e = io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	if files["records.csv"] == nil || files["readme.txt"] == nil {
		t.Fatal("CSV or readme absent")
	}
	return csvTestJSON(t, files["records.csv"], files["readme.txt"])
}

// TestExportPublicPostsColumns は自動投稿の除外・本文の一本化・原本対応・数式保護を実セルで確認する。
func TestExportPublicPostsColumns(t *testing.T) {
	source := map[string]any{"thread_key": "123", "post_number": 8, "source_event_sha256": "original", "client": map[string]any{"resolved_ip": "192.0.2.1"}, "identity": map[string]any{"post_numbers": []int{8, 9}}, "content": map[string]any{"body": "=1+1", "name": "INPUT_NAME_PRIVATE", "mail": "INPUT_MAIL_PRIVATE", "title": "INPUT_TITLE_PRIVATE", "public_title": "公開件名", "public_posts": []any{
		map[string]any{"number": 8, "kind": "user", "name": "公開名", "mail": "", "body": "=1+1", "identity": map[string]any{"id": "12345678901234567890", "date_text": "日時表示", "slip": "表示", "trip": "トリップ", "cap": "キャップ"}},
		map[string]any{"number": 9, "kind": "system", "name": "AUTO_END_NAME", "mail": "AUTO_END_MAIL", "body": "AUTO_END_BODY", "identity": map[string]any{"id": "AUTO_END_ID"}},
	}}}
	before, _ := json.Marshal(source)
	rows := []map[string]any{source, {"thread_key": "456", "content": map[string]any{"body": "公開投稿未記録"}}}
	table, err := prepareExportCSV(rows)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = table.write(&out); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(out.Bytes()[3:])).ReadAll()
	if err != nil || len(records) != 3 {
		t.Fatal("CSV user rows", err)
	}
	indexes := map[string]int{}
	for i, name := range records[0] {
		indexes[name] = i
		if strings.HasPrefix(name, "content.") || strings.HasPrefix(name, "input_") || strings.HasPrefix(name, "identity") || name == "input_body" || name == "body" {
			t.Fatal("redundant column", name)
		}
	}
	expected := map[string]string{"post_number": "8", "public_body": "'=1+1", "public_name": "公開名", "public_mail": `\E`, "public_id": "'12345678901234567890", "public_date_text": "日時表示", "public_slip": "表示", "public_trip": "トリップ", "public_cap": "キャップ", "source_event_sha256": "original", "client.resolved_ip": "192.0.2.1", "thread_key": "123", "public_title": "公開件名"}
	for name, want := range expected {
		index, ok := indexes[name]
		if !ok || records[1][index] != want {
			t.Fatalf("%s: got %q, want %q", name, records[1][index], want)
		}
	}
	if bytes.Contains(out.Bytes(), []byte("INPUT_")) {
		t.Fatal("input fields exported")
	}
	if bytes.Contains(out.Bytes(), []byte("AUTO_END_")) {
		t.Fatal("automatic post exported")
	}
	if records[2][indexes["public_body"]] != "公開投稿未記録" {
		t.Fatal("input body lost without public fields")
	}
	after, _ := json.Marshal(source)
	if !bytes.Equal(before, after) {
		t.Fatal("source mutated")
	}
	if count, err := countCSVRecords(out.Bytes()); err != nil || count != 2 {
		t.Fatal("user row count", count, err)
	}
	if !bytes.Contains(table.readme(), []byte("終了案内などの自動投稿は含めません")) {
		t.Fatal("user-only explanation")
	}
}

// TestExportResponseTimeOnlyWhenObserved は全欠測時の列省略と、一件でも観測がある場合のnull保持を確認する。
func TestExportResponseTimeOnlyWhenObserved(t *testing.T) {
	missing := map[string]any{"thread_key": "123", "time": map[string]any{"response_finished_at_ns": nil}}
	table, err := prepareExportCSV([]map[string]any{missing})
	if err != nil {
		t.Fatal(err)
	}
	const key = "time.response_finished_at_jst"
	for _, header := range table.headers {
		if header == key {
			t.Fatal("all-null response time column exported")
		}
	}
	if _, ok := table.rows[0][key]; ok {
		t.Fatal("unobserved response time retained")
	}
	at := domain.Time(1800000000123456789)
	observed := map[string]any{"thread_key": "456", "time": map[string]any{"response_finished_at_ns": at}}
	table, err = prepareExportCSV([]map[string]any{missing, observed})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = table.write(&out); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(out.Bytes()[3:])).ReadAll()
	if err != nil || len(records) != 3 {
		t.Fatal("CSV", err)
	}
	index := -1
	for i, header := range records[0] {
		if header == key {
			index = i
		}
	}
	if index < 0 {
		t.Fatal("observed response time omitted")
	}
	if records[1][index] != `\N` || records[2][index] != time.Unix(0, int64(at)).In(domain.JST).Format(time.RFC3339Nano) {
		t.Fatal("response time values", records)
	}
	if submissionObject(missing["time"])["response_finished_at_ns"] != nil {
		t.Fatal("source changed")
	}
}
