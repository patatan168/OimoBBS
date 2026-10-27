// 未受理記録の保全状態と提出範囲を説明し、出力ファイルへmanifest署名を付ける。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"time"
)

// writeRejectedZIP は未受理記録と実際の保全状態を明示して署名ZIPを生成する。
func (s *Store) writeRejectedZIP(c Case, v Export, actor domain.ID, rows []app.RejectedEvidence, now time.Time) error {
	m := Manifest{Schema: "evidence-export-v1", RecordKind: rejectedExportKind, ID: v.ID, Case: c.ID, Actor: actor, Generated: now.In(domain.JST).Format(time.RFC3339Nano), Until: v.Until, Scope: c.Scope, Columns: v.Columns, Count: uint32(len(rows)), Sources: []domain.Hash{}, Missing: []domain.ID{}, Files: []exportFile{}, KeyID: 10, Completeness: "partial"}
	projected := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		data, e := row.Project(v.Columns)
		if e != nil {
			return e
		}
		data["committed_at_jst"] = time.Unix(0, int64(row.Committed)).In(domain.JST).Format(time.RFC3339Nano)
		data["preservation"] = "ordinary_retention"
		if v.RejectedHeld {
			data["preservation"] = "case_hold"
			data["held_until_ns"] = c.RetentionUntil()
		}
		projected = append(projected, data)
		m.Sources = append(m.Sources, row.SourceSHA, row.DecisionSHA)
	}
	retention := "案件保全コピーは作成しておらず、原本の7日の保持期限は延長しません。\n"
	if v.RejectedHeld {
		retention = "案件保全した接続・結果のコピーを使用し、案件の保全期限まで保持します。\n"
	}
	readme := []byte(`OimoBBS 未受理ログ

提出可能な接続・処理結果を含む部分記録です。投稿本文・認証秘密は含めません。
接続観測がない場合はnot_collectedを記載します。
接続元は保存時に観測・解決された値、User-Agentは未検証の申告値です。
` + retention + zipSignatureReadme)
	return s.writeProjectedZIP(c, v, m, projected, readme)
}
