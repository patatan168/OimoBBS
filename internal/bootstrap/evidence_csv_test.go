// 実HTTPで取得したCSVを読み、列の値と選択情報を検査する共通補助。
package bootstrap

import (
	"bytes"
	"encoding/csv"
	"testing"
)

func evidenceCSVRows(t *testing.T, raw []byte) []map[string]string {
	t.Helper()
	data, e := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))).ReadAll()
	if e != nil || len(data) == 0 {
		t.Fatal("CSV", e)
	}
	rows := []map[string]string{}
	for _, cells := range data[1:] {
		row := map[string]string{}
		for i, key := range data[0] {
			row[key] = cells[i]
		}
		rows = append(rows, row)
	}
	return rows
}
