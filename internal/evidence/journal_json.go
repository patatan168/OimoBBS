// journal専用の固定JSONを一つのbufferへ組み、base64本文の汎用Marshalと再走査を省く。
package evidence

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/jsonencode"
	"strconv"
)

// marshalJournalOperation は内部生成した署名イベントと制御操作を既存順で符号化する。
// 本文と署名は元byteからbase64化し、任意の文字列を無escapeで挿入しない。
// 戻り値のvalue長は非必須記録の容量計算用。frame・値・署名の完全検査は後続で維持する。
func marshalJournalOperation(event Event, payload, signature []byte, seq uint64, committed domain.Time, optional bool) ([]byte, int, error) {
	if event.RecordID == (domain.ID{}) {
		return nil, 0, errors.New("zero ID")
	}
	id := event.RecordID.String()
	raw := make([]byte, 0, base64.StdEncoding.EncodedLen(len(payload))+base64.StdEncoding.EncodedLen(len(signature))+len(event.Schema)+2*len(event.Kind)+1024)
	raw = append(raw, `{"schema":1,"seq":"`...)
	raw = strconv.AppendUint(raw, seq, 10)
	raw = append(raw, `","committed_at_ns":"`...)
	raw = strconv.AppendInt(raw, int64(committed), 10)
	raw = append(raw, `","actor":{"kind":"system","id":null,"reason_code":"evidence","request_hmac":null,"idempotency_hmac":null,"key_id":null},"expected_seq":"`...)
	raw = strconv.AppendUint(raw, seq-1, 10)
	raw = append(raw, `","mutations":[{"collection":`...)
	kindStart := len(raw)
	raw = jsonencode.AppendString(raw, event.Kind)
	kindEnd := len(raw)
	raw = append(raw, `,"key":"`...)
	raw = append(raw, id...)
	raw = append(raw, `","expected_revision":"0","value":`...)
	start := len(raw)
	raw = append(raw, `{"schema":`...)
	raw = jsonencode.AppendString(raw, event.Schema)
	raw = append(raw, `,"record_id":"`...)
	raw = append(raw, id...)
	raw = append(raw, `","kind":`...)
	raw = append(raw, raw[kindStart:kindEnd]...)
	raw = append(raw, `,"payload_base64":"`...)
	raw = base64.StdEncoding.AppendEncode(raw, payload)
	raw = append(raw, `","payload_sha256":"`...)
	raw = hex.AppendEncode(raw, event.PayloadSHA[:])
	raw = append(raw, `","previous_event_sha256":"`...)
	raw = hex.AppendEncode(raw, event.PreviousSHA[:])
	raw = append(raw, `","event_sha256":"`...)
	raw = hex.AppendEncode(raw, event.EventSHA[:])
	raw = append(raw, `","signing_key_id":`...)
	raw = strconv.AppendUint(raw, uint64(event.SigningKeyID), 10)
	raw = append(raw, `,"signature_base64":"`...)
	raw = base64.StdEncoding.AppendEncode(raw, signature)
	raw = append(raw, `"}`...)
	valueSize := len(raw) - start
	raw = append(raw, `,"expires_at_ns":null}],"result":{"code":"`...)
	if optional {
		raw = append(raw, `saved","target_ids":[]`...)
	} else {
		raw = append(raw, `evidence_saved","target_ids":["`...)
		raw = append(raw, id...)
		raw = append(raw, `"]`...)
	}
	raw = append(raw, `,"request_key_hmac":null,"request_hmac":null,"key_id":null,"expires_at_ns":null}}`...)
	return raw, valueSize, nil
}
