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
		{"record_id": "001", "connection": map[string]any{"peer": map[string]any{"ip": "2001:db8::1", "port": 443}}, "content": map[string]any{"body": "日本語,\"引用\"\n次の行", "title": "=1+1", "mail": "", "name": `\N`}, "committed_at_ns": domain.Time(1800000000123456789), "http_status": nil, "missing_fields": []any{map[string]any{"field": "http_status", "reason": "not_observed"}}},
		{"record_id": "002", "content": map[string]any{"body": "'元の引用", "title": " +SUM(1,2)"}, "http_status": 200},
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
	expected := map[string]string{"connection.peer.ip": "2001:db8::1", "connection.peer.port": "443", "content.body": "日本語,\"引用\"\n次の行", "content.title": "'=1+1", "content.mail": `\E`, "content.name": `'\N`, "committed_at_jst": time.Unix(0, 1800000000123456789).In(domain.JST).Format(time.RFC3339Nano), "http_status": `\N`}
	for key, want := range expected {
		i, exists := index[key]
		if !exists || records[1][i] != want {
			t.Fatal("cell", key, records[1][i], want)
		}
	}
	if records[2][index["committed_at_jst"]] != "" || records[2][index["content.body"]] != "''元の引用" || records[2][index["content.title"]] != "' +SUM(1,2)" {
		t.Fatal("missing or text prefix")
	}
	if count, e := countCSVRecords(out.Bytes()); e != nil || count != 2 {
		t.Fatal("multiline count", count, e)
	}
	for _, meaning := range []string{"直近の接続相手", "投稿入力の本文", "記録の確定時刻", "欠測項目"} {
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
