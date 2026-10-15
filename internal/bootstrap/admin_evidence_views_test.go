// HTTP日付表示が元の案件・署名型を変更せず、未確定時刻をnullにすることを検査する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
)

func TestEvidenceCaseHTTPDatesPreserveSavedValues(t *testing.T) {
	at := domain.Time(time.Date(2026, 10, 5, 15, 1, 2, 123456789, time.UTC).UnixNano())
	c := disclosure.Case{ID: domain.NewID(), Creator: domain.NewID(), Created: at, Until: at + 100, Review: at - 100, Closed: at + 1,
		Scope:   disclosure.Scope{Board: domain.NewID(), From: at - 1, To: at, Records: []domain.ID{}},
		Items:   []disclosure.Item{{Record: domain.NewID(), Expires: at + 2}},
		Exports: []disclosure.Export{{ID: domain.NewID(), Created: at + 3, Until: at + 4, Columns: []string{}}},
	}
	before, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	v := evidenceCaseHTTPValue(c)
	assertEvidenceSavedDateAliases(t, v, c)
	assertEvidenceViewLegacyValues(t, c, v, before)
}

// assertEvidenceSavedDateAliases は各表示日付が現在状態で補完されず保存日時に一致することを確認する。
func assertEvidenceSavedDateAliases(t *testing.T, v evidenceCaseHTTPView, c disclosure.Case) {
	t.Helper()
	if v.CreatedAt != "2026-10-05T15:01:02.123456789Z" || v.HoldUntil != adminDate(c.Until) || *v.ReviewAt != adminDate(c.Review) || *v.ClosedAt != adminDate(c.Closed) {
		t.Fatal("case dates changed", v)
	}
	if v.Scope.From != adminDate(c.Scope.From) || v.Scope.To != adminDate(c.Scope.To) || v.Items[0].SourceExpiresAt != adminDate(c.Items[0].Expires) {
		t.Fatal("scope or source dates changed")
	}
	if v.Exports[0].CreatedAt != adminDate(c.Exports[0].Created) || v.Exports[0].RetentionUntil != adminDate(c.Exports[0].Until) {
		t.Fatal("export dates changed")
	}
}

// assertEvidenceViewLegacyValues は日付別名が保存型と旧クライアントの読取りへ影響しないことを確認する。
func assertEvidenceViewLegacyValues(t *testing.T, c disclosure.Case, v evidenceCaseHTTPView, before []byte) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"data": c, "dates": v})
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Data disclosure.Case `json:"data"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(c)
	legacy, _ := json.Marshal(response.Data)
	if !bytes.Equal(before, after) || !bytes.Equal(before, legacy) {
		t.Fatal("saved values or legacy response changed")
	}
}

func TestEvidenceCaseHTTPUnknownDatesAndEmptyCollections(t *testing.T) {
	view := evidenceCaseHTTPValue(disclosure.Case{})
	if view.ReviewAt != nil || view.ClosedAt != nil || view.Items != nil || view.Exports != nil {
		t.Fatal("unknown dates or nil collections replaced")
	}
	view = evidenceCaseHTTPValue(disclosure.Case{Items: []disclosure.Item{}, Exports: []disclosure.Export{}})
	if view.Items == nil || view.Exports == nil {
		t.Fatal("empty collections became null")
	}
	if evidenceCaseHTTPValues(nil) != nil || len(evidenceCaseHTTPValues([]disclosure.Case{})) != 0 {
		t.Fatal("list shape changed")
	}
	rows := []map[string]any{{"clock": "original"}}
	if evidenceResultHTTPValue(rows) != nil {
		t.Fatal("evidence projection included in date fields")
	}
}

// assertEvidenceExportHTTPDates はAPI生成結果にも保存済みの提出期限が返ることを検査する。
func assertEvidenceExportHTTPDates(t *testing.T, body string, export disclosure.Export) {
	t.Helper()
	var response struct {
		Result evidenceExportHTTPView `json:"result_dates"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	if response.Result.CreatedAt != adminDate(export.Created) || response.Result.RetentionUntil != adminDate(export.Until) {
		t.Fatal("export result dates missing", body)
	}
}
