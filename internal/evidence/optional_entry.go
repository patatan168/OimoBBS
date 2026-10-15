// 制限領域へコピーしたHTTP原本の署名・日付・サイト束縛を照合し、部分列だけを提供する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"strconv"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// VerifyOptionalEntry は信頼済み鍵と期待サイトで元bytesを検証し、独立した固定HTTP型を返す。
// 時間満了の扱いは呼出元の責務。保全コピーは案件期限、正本取得は元の7日期限で判定する。
// 単独署名と元sourceの一致を検証するが、前後の全履歴の連続性・観測の完全性は証明しない。
func VerifyOptionalEntry(entry Entry, site domain.ID, key ed25519.PublicKey) (OptionalEvidence, error) {
	var out OptionalEvidence
	if site == (domain.ID{}) || len(entry.Payload) > MaxOptionalRecordBytes+(1<<10) || ValidateOptionalPayload(entry.Event.Kind, entry.Payload) != nil {
		return out, store.ErrCorrupt
	}
	var p OptionalPayload
	if strictjson.Decode(entry.Payload, &p) != nil || p.Record.Site != site || p.Owner != OptionalOwner(site) || entry.Event.RecordID != p.Record.ID {
		return out, store.ErrCorrupt
	}
	day, e := strconv.ParseUint(time.Unix(0, int64(p.Record.Received)).UTC().Format("20060102"), 10, 64)
	if e != nil || uint64(p.Day) != day {
		return out, store.ErrCorrupt
	}
	raw, e := Verify(Source{p.Owner, uint64(p.Day), uint64(p.Seq)}, entry.Event, entry.Event.PreviousSHA, 10, key)
	if e != nil || !bytes.Equal(raw, entry.Payload) {
		return out, store.ErrCorrupt
	}
	return OptionalEvidence{p.Owner, p.Day, p.Seq, entry.Event.EventSHA, p.Record}, nil
}
