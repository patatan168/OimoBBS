// 操作なしHTTP案件の固定コピーを、既存の提出ZIP・一回取得・期限回収へ接続する。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"slices"
	"time"
)

// validateHTTPObservationExport は本文列や他種別の参照をHTTP提出へ混ぜない。
func validateHTTPObservationExport(c Case, v Export) error {
	if c.HTTP == nil || !c.HTTP.Unbound || v.HTTPSelection == (domain.Hash{}) || len(v.RejectedSources) != 0 || v.RejectedHeld || !app.ValidRejectedColumns(v.Columns) || !validRejectedExportMetadata(v) {
		return store.ErrCorrupt
	}
	return nil
}

// writeHTTPObservationZIP は案件コピーだけを読み、部分観測と欠落を署名manifestへ残す。
func (s *Store) writeHTTPObservationZIP(c Case, v Export, actor domain.ID, now time.Time) error {
	if e := validateHTTPObservationExport(c, v); e != nil {
		return e
	}
	rows, e := s.HTTPRecords(c, now)
	if e != nil {
		return e
	}
	m := Manifest{Schema: "evidence-export-v1", RecordKind: "http_observation", ID: v.ID, Case: c.ID, Actor: actor, Generated: now.In(domain.JST).Format(time.RFC3339Nano), Until: v.Until, Scope: c.Scope, Columns: v.Columns, Count: uint32(len(rows)), Sources: []domain.Hash{}, Missing: []domain.ID{}, Files: []exportFile{}, KeyID: 10, Completeness: "partial_observation"}
	projected := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		data := row.ProjectUnbound(slices.Contains(v.Columns, "connection"))
		data["preservation"] = "case_hold"
		data["held_until_ns"] = c.Until
		projected = append(projected, data)
		m.Sources = append(m.Sources, row.SourceSHA)
	}
	for _, item := range c.HTTP.Items {
		if item.State != "held" {
			m.Missing = append(m.Missing, item.Record)
		}
	}
	readme := []byte("OimoBBS HTTP観測の提出用記録\nこのZIPは選択項目のbytesを新たに署名しています。source_event_sha256は原記録への対応付け用で、部分列の原本署名ではありません。\n受理操作に結び付かない受付前拒否・閲覧の部分観測です。スレッド所属、投稿本文、送信完了・相手先受領を証明しません。connection列のみ接続値を含みます。接続は直近hop、UAは未検証の申告値です。案件コピーは保全期限で保持し、原本の7日期限は変更しません。欠落対象はmanifestに明記します。\nmanifest.sigはmanifest.jsonの元bytesのSHA-256へEd25519で署名した64bytesです。public-keys.jsonの鍵を別途信頼済み公開鍵と照合してください。時刻の桁数は時計精度を保証しません。暗号化ZIPではありません。\n")
	return s.writeProjectedZIP(c, v, m, projected, readme)
}
