// 実データや署名鍵を使わず、提出CSVと同じ整形処理で確認用サンプルを作成する。
package disclosure

import (
	"archive/zip"
	"bytes"
	"time"

	"oimobbs/internal/domain"
)

// SampleZIP は架空の受理投稿・未受理・HTTP観測を含む未署名の見本を返す。
// 実提出物には別途manifest・署名・公開鍵が付く。サンプルは案件を作成しない。
func SampleZIP() ([]byte, error) {
	at := domain.Time(time.Date(2026, 10, 12, 0, 1, 2, 123456789, domain.JST).UnixNano())
	rows := []map[string]any{
		{"record_id": "sample-accepted", "record_kind": "accepted_post", "board_id": "sample-board", "thread_key": "1791730862", "post_number": 1, "committed_at_ns": at, "source_event_sha256": "sample-source-reference", "completeness": "partial", "result": map[string]any{"attempt_result": "accepted", "decision_at_ns": at, "recovered": false}, "connection": map[string]any{"peer": map[string]any{"ip": "192.0.2.10", "port": 54321}, "local": map[string]any{"ip": "192.0.2.20", "port": 443}, "http_version": "HTTP/1.1", "transport": "tls"}, "request": map[string]any{"method": "POST", "route": "posting", "canonical_host": "bbs.example.invalid"}, "content": map[string]any{"name": "サンプル投稿者", "mail": "sage", "title": "架空のスレッド", "body": "これは提出形式を確認する架空の投稿です。"}},
		{"record_id": "sample-rejected", "record_kind": "not_accepted", "board_id": "sample-board", "committed_at_ns": at, "attempt_result": "rejected", "connection": nil, "connection_missing_reason": "not_collected", "completeness": "partial"},
		{"record_id": "sample-http", "record_kind": "http_observation", "board_id": "sample-board", "received_at_ns": at, "finished_at_ns": at + domain.Time(time.Millisecond), "monotonic_elapsed_ns": domain.U64(1000000), "http_status": 403, "outcome": "rejected", "completeness": "partial_observation"},
	}
	table, e := prepareExportCSV(rows)
	if e != nil {
		return nil, e
	}
	var out bytes.Buffer
	z := zip.NewWriter(&out)
	csv, e := z.Create("records.csv")
	if e != nil {
		return nil, e
	}
	if e = table.write(csv); e != nil {
		return nil, e
	}
	readme, e := z.Create("readme.txt")
	if e != nil {
		return nil, e
	}
	if _, e = readme.Write(append([]byte("提出用ログの架空サンプル\n実在の投稿・接続・原記録は含みません。署名のない表示確認用の見本です。提出には使えません。\n実際の提出ZIPにはrecords.csv・readme.txtのほか、manifest.json・manifest.sig・public-keys.jsonが含まれます。項目は選択内容と保存記録によって変わります。\n"), table.readme()...)); e != nil {
		return nil, e
	}
	if e = z.Close(); e != nil {
		return nil, e
	}
	return out.Bytes(), nil
}
