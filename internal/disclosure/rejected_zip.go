// 未受理と非保全を提出物内でも明記し、選択bytesへ既存のmanifest署名を付ける。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"time"
)

// writeRejectedZIP は未受理・通常期限内であることを明示して選択bytesへ署名する。
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
	readme := []byte("OimoBBS 未受理ログの提出用記録\nこのZIPは未受理の接続/結果だけを選択して新たに署名したものです。受理された投稿や本文の提出物ではありません。本文/資格は含めず、接続がない場合はnot_collectedを明示します。案件保全コピーは作成しておらず、元の7日期限は延長しません。\n接続はサーバーが観測した直近hop、ヘッダは未検証の申告値です。記録はpartialです。source_event_sha256は元記録との対応で、部分列の原本署名ではありません。\nmanifest.sigはmanifest.jsonの元bytesのSHA-256に対するEd25519署名です。公開鍵は別途信頼済み鍵へ照合してください。相手先への送信・受領は証明しません。\n")
	if v.RejectedHeld {
		readme = []byte("OimoBBS 未受理ログの案件保全提出用記録\n接続/結果だけを案件保全したコピーから、選択bytesを新たに署名しています。未受理を受理投稿として扱わず、本文/投稿資格は含めません。元の7日期限と案件コピーの期限は別です。元署名hashは対応付け用で、投影した部分列の元署名ではありません。記録はpartial、ヘッダは未検証の申告値です。相手先への送信・受領は証明しません。manifest.sigはmanifest.jsonのSHA-256に対するEd25519署名です。公開鍵は別途信頼済み鍵へ照合してください。\n")
	}
	return s.writeProjectedZIP(c, v, m, projected, readme)
}
