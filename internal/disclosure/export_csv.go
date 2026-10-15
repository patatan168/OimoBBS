// 選択済み記録だけをCSVへ平坦化し、同じカラム一覧からREADMEを生成する。
package disclosure

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type exportCSV struct {
	headers []string
	rows    []map[string]any
	types   map[string]map[string]bool
}

// prepareExportCSV はJSONと同じ選択済み値を正規化する。数字はfloat64へ変換しない。
func prepareExportCSV(projected []map[string]any) (exportCSV, error) {
	table := exportCSV{rows: make([]map[string]any, 0, len(projected)), types: map[string]map[string]bool{}}
	for _, row := range projected {
		raw, e := json.Marshal(row)
		if e != nil {
			return table, e
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value map[string]any
		if e = decoder.Decode(&value); e != nil {
			return table, e
		}
		flat := map[string]any{}
		simplifyExportRecord(value)
		flattenExportCSV("", value, flat)
		table.rows = append(table.rows, flat)
		for key, value := range flat {
			if table.types[key] == nil {
				table.types[key] = map[string]bool{}
			}
			table.types[key][csvValueType(value)] = true
		}
	}
	if len(table.types) == 0 {
		table.types["record_id"] = map[string]bool{"string": true}
	}
	for key := range table.types {
		table.headers = append(table.headers, key)
	}
	sort.Strings(table.headers)
	return table, nil
}

// flattenExportCSV はオブジェクトをドット区切りの列へ展開し、配列は一つのJSONセルに保つ。
func flattenExportCSV(path string, value any, out map[string]any) {
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		out[path] = value
		return
	}
	for key, child := range object {
		name := key
		if path != "" {
			name = path + "." + key
		}
		flattenExportCSV(name, child, out)
	}
}

func csvValueType(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "boolean"
	case []any:
		return "array"
	default:
		return "object"
	}
}

// csvCell はnull・空文字・不存在を分け、表計算の数式と長い数字文字列の自動変換を防ぐ。
func csvCell(value any) (string, error) {
	if value == nil {
		return `\N`, nil
	}
	if text, ok := value.(string); ok {
		if text == "" {
			return `\E`, nil
		}
		head := strings.TrimLeft(text, " \t\r\n")
		dangerous := strings.ContainsAny(text[:1], "'\\\t\r\n") || head != "" && strings.ContainsAny(head[:1], "=+-@")
		longDigits := len(text) > 15 && strings.Trim(text, "0123456789") == ""
		if dangerous || longDigits {
			text = "'" + text
		}
		return text, nil
	}
	raw, e := json.Marshal(value)
	return string(raw), e
}

// write はUTF-8 BOMとヘッダを出力する。セル内改行を含む記録も一つのCSV行として扱う。
func (table exportCSV) write(w io.Writer) error {
	if _, e := io.WriteString(w, "\xef\xbb\xbf"); e != nil {
		return e
	}
	writer := csv.NewWriter(w)
	if e := writer.Write(table.headers); e != nil {
		return e
	}
	for _, row := range table.rows {
		cells := make([]string, len(table.headers))
		for i, key := range table.headers {
			if value, exists := row[key]; exists {
				cell, e := csvCell(value)
				if e != nil {
					return e
				}
				cells[i] = cell
			}
		}
		if e := writer.Write(cells); e != nil {
			return e
		}
	}
	writer.Flush()
	return writer.Error()
}

// readme は実際に出力する全カラムの型・意味と、特殊値の読み方を説明する。
func (table exportCSV) readme() []byte {
	var text strings.Builder
	text.WriteString("\nrecords.csv の読み方\nUTF-8（BOM付き）、カンマ区切り、先頭行はカラム名です。1行は1記録です。カンマ・引用符・改行を含むセルはCSVの引用符で囲みます。ドット区切りは元の情報の階層です。配列はセル内のJSONです。選択していない情報の列は出力しません。\n空欄はその記録に項目がないこと、\\Nはnull（不明・未記録等）、\\Eは空文字を表します。欠測理由はmissing_fieldsやmissing_reasonの列で確認してください。先頭のアポストロフィは表計算の数式実行・長い数字文字列の桁落ちを防ぐ表示用接頭辞です。元値を読む場合は先頭から一つだけ除去します。元値がアポストロフィで始まる場合も一つ付加しています。\n日時は_jstで示すRFC3339の日本時間（+09:00）に統一しています。monotonic_elapsed_nsは日時ではなく単調時計の経過ナノ秒です。同じ情報の重複列は省略しています。manifestの数値時刻は署名検証用のUnix epochからのナノ秒です。正確なID・時刻・ハッシュを扱うには表計算で列を文字列として読み込んでください。時刻の桁数は時計精度を保証しません。\n配列: missing_fieldsはfield（欠測項目）/reason（理由）の一覧。selected_headers/reported_headersはname（ヘッダ名）/representation（取得形態）/valuesの一覧で、values内のdisplayは表示値、base64は元bytesです。verified_proxy_chainは認証済み経路のip/port一覧。public_postsは受理時の公開投稿（number/kind/visibility/created_at_jst/name/mail/body/identity）。rule_idsは適用ルールID。optional_httpは関連HTTP観測と元署名の一覧で、受理投稿そのものや欠測なしの証明ではありません。\n\nカラム一覧（このCSVに含まれる列だけ）\n")
	for _, key := range table.headers {
		types := []string{}
		for typ := range table.types[key] {
			types = append(types, typ)
		}
		sort.Strings(types)
		fmt.Fprintf(&text, "- %s [%s]: %s\n", key, strings.Join(types, "/"), csvColumnMeaning(key))
	}
	return []byte(text.String())
}

// countCSVRecords は行中の改行を件数に含めず、ヘッダの重複と行の列数も検査する。
func countCSVRecords(raw []byte) (uint32, error) {
	reader := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))))
	headers, e := reader.Read()
	if e != nil {
		return 0, ErrInvalid
	}
	seen := map[string]bool{}
	for _, key := range headers {
		if key == "" || seen[key] {
			return 0, ErrInvalid
		}
		seen[key] = true
	}
	var count uint32
	for {
		_, e = reader.Read()
		if e == io.EOF {
			return count, nil
		}
		if e != nil {
			return 0, ErrInvalid
		}
		count++
	}
}
