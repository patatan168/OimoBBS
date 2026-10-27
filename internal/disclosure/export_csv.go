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
	selected, err := SubmissionRecords(projected)
	if err != nil {
		return table, err
	}
	for _, value := range selected {
		for _, flat := range exportCSVRows(value) {
			table.rows = append(table.rows, flat)
			for key, value := range flat {
				if table.types[key] == nil {
					table.types[key] = map[string]bool{}
				}
				table.types[key][csvValueType(value)] = true
			}
		}
	}
	// 別HTTP記録から終了時刻を取得できた行がない場合は、空の列を作らない。
	const responseTime = "time.response_finished_at_jst"
	if types := table.types[responseTime]; len(types) == 1 && types["null"] {
		delete(table.types, responseTime)
		for _, row := range table.rows {
			delete(row, responseTime)
		}
	}
	if len(table.types) == 0 {
		table.types["record_kind"] = map[string]bool{"string": true}
	}
	for key := range table.types {
		table.headers = append(table.headers, key)
	}
	sort.Strings(table.headers)
	return table, nil
}

// flattenExportCSV はオブジェクトをドット区切りの列へ展開し、配列はJSONセルに保つ。
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
	text.WriteString(`
records.csv の読み方

UTF-8（BOM付き）のカンマ区切りCSVで、先頭行がカラム名です。
投稿者本人の1投稿につき1行です。終了案内などの自動投稿は含めません。
未受理・HTTP観測など公開投稿がない記録も1記録につき1行です。
manifestのcountはCSVのデータ行数です。セル内の改行は件数に含めません。

投稿の対象と本文
- board_key: 投稿時に使用された板キー。URL別名を含みます。
- thread_key: スレッド番号。
- post_number: レス番号。
- public_body: 正規化・秘密除去後の投稿者本人の本文。
- public_で始まる列: 受理時に確定した名前・メール・件名・IDなどの公開表示。
本文と公開表示は受理時の記録です。現在の公開状態を示すものではありません。
公開投稿がない記録の公開列は空欄です。ドット区切りは情報の階層、配列はセル内のJSONです。

日時と欠測
日時の_jst列はRFC3339の日本時間（+09:00）です。配列内の日時も同じ形式です。
応答終了時刻は同じ要求の別保存HTTP記録がある場合だけ出力します。
記録がない投稿は\Nで、全行が欠測なら列を省略します。欠測は応答が終了しなかった証明ではありません。
応答終了時刻はサーバーのHTTP処理が戻った時刻で、送信完了や相手先の受領時刻ではありません。
空欄はその記録に項目がないこと、\Nはnull（不明・未記録等）、\Eは空文字を表します。
欠測理由はmissing_fieldsやmissing_reasonの列で確認できます。保存されていない値は補いません。

セルの読み込み
カンマ・引用符・改行を含むセルはCSVの引用符で囲みます。
先頭のアポストロフィは数式実行・長い数字文字列の桁落ちを防ぐ接頭辞です。
元値を読む場合は先頭から1つだけ除きます。元値がアポストロフィで始まる場合も1つ付加しています。
正確なID・時刻・ハッシュは、表計算で列を文字列として読み込んでください。
時刻の桁数は時計精度を保証しません。manifestの数値時刻はUnix epochからのナノ秒です。

Cookie由来のIDと応答情報
Cookie由来のIDは同じ匿名Cookieによる投稿の照合用HMACです。
本人の一致は保証せず、Cookieの削除・再発行で変わります。
missing_fieldsはfield（欠測項目）/reason（理由）の一覧です。
応答の状態コード・処理結果・原本参照はresponse_http_status・response_outcome・response_source_event_sha256です。
同じ投稿要求に対応する応答だけを含め、UA・接続先・受付日時は重ねません。
再送・確認・閲覧など別要求の記録は投稿ログへ含めません。

カラム一覧（このCSVに含まれる列だけ）
`)
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
