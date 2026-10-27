// 案件管理HTTPへRFC3339Nanoの日付別名を付け、保存型と署名原本は維持する。
package bootstrap

import (
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
)

type evidenceScopeHTTPView struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type evidenceItemHTTPView struct {
	Record          domain.ID `json:"record_id"`
	SourceExpiresAt string    `json:"source_expires_at"`
}

type evidenceExportHTTPView struct {
	ID             domain.ID `json:"export_id"`
	CreatedAt      string    `json:"created_at"`
	RetentionUntil string    `json:"retention_until"`
}

type evidenceCaseHTTPView struct {
	ID        domain.ID                `json:"case_id"`
	CreatedAt string                   `json:"created_at"`
	HoldUntil string                   `json:"hold_until"`
	ReviewAt  *string                  `json:"review_at"`
	ClosedAt  *string                  `json:"closed_at"`
	Scope     evidenceScopeHTTPView    `json:"scope"`
	Items     []evidenceItemHTTPView   `json:"items"`
	Exports   []evidenceExportHTTPView `json:"exports"`
}

// evidenceOptionalDate は未確定の0を1970年の日時と誤表示せずnullにする。
func evidenceOptionalDate(at domain.Time) *string {
	if at == 0 {
		return nil
	}
	formatted := adminDate(at)
	return &formatted
}

func evidenceExportHTTPValue(v disclosure.Export) evidenceExportHTTPView {
	return evidenceExportHTTPView{v.ID, adminDate(v.Created), adminDate(v.Until)}
}

// evidenceCaseHTTPValue は管理用日時を保存値から生成する。現在時刻や設定で補完しない。
func evidenceCaseHTTPValue(c disclosure.Case) evidenceCaseHTTPView {
	v := evidenceCaseHTTPView{
		ID: c.ID, CreatedAt: adminDate(c.Created), HoldUntil: adminDate(c.Until),
		ReviewAt: evidenceOptionalDate(c.Review), ClosedAt: evidenceOptionalDate(c.Closed),
		Scope: evidenceScopeHTTPView{adminDate(c.Scope.From), adminDate(c.Scope.To)},
	}
	if c.Items != nil {
		v.Items = make([]evidenceItemHTTPView, len(c.Items))
	}
	for i, item := range c.Items {
		v.Items[i] = evidenceItemHTTPView{item.Record, adminDate(item.Expires)}
	}
	if c.Exports != nil {
		v.Exports = make([]evidenceExportHTTPView, len(c.Exports))
	}
	for i, export := range c.Exports {
		v.Exports[i] = evidenceExportHTTPValue(export)
	}
	return v
}

func evidenceCaseHTTPValues(cases []disclosure.Case) []evidenceCaseHTTPView {
	if cases == nil {
		return nil
	}
	values := make([]evidenceCaseHTTPView, len(cases))
	for i, c := range cases {
		values[i] = evidenceCaseHTTPValue(c)
	}
	return values
}

// evidenceResultHTTPValue は生成/再開の管理結果だけを表示型へ変換する。
func evidenceResultHTTPValue(value any) any {
	if export, ok := value.(disclosure.Export); ok {
		return evidenceExportHTTPValue(export)
	}
	return nil
}
