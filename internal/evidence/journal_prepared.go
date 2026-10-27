// 一回の一括追記内だけ、同じ完全payloadの業務検査結果を共有する。
package evidence

import (
	"bytes"
	"errors"
	"oimobbs/internal/domain"
)

type preparedPayload struct {
	kind   string
	raw    []byte
	source Source
}

// validatePreparedPayload はsource/hash/署名の再検査後、同じ元byteの業務検査だけを再利用する。
// 内容・種別が異なる場合と再起動時は通常の完全検査を行う。WALの検査と耐久境界は省略しない。
func (j *Journal) validatePreparedPayload(event Event, raw []byte) error {
	if known, ok := j.preparedPayloads[event.PayloadSHA]; ok && known.kind == event.Kind && bytes.Equal(known.raw, raw) {
		return nil
	}
	return j.validatePayload(event.Kind, raw)
}

// payloadForValidation は同じ追記内の検査済み元byteとsourceだけを借り、再復号を避ける。
// sourceはprepareSeal成功後だけ登録する。正規base64との完全一致に加え、呼出元で元byte・sourceのhashと署名を必ず再検証する。
func (j *Journal) payloadForValidation(event Event) ([]byte, Source, error) {
	if known, ok := j.preparedPayloads[event.PayloadSHA]; ok && known.kind == event.Kind && known.source.Owner != (domain.ID{}) && matchesPayloadEncoding(known.raw, event.Payload) {
		return known.raw, known.source, nil
	}
	payload, err := decodePayload(event)
	if err != nil || !matchesPayloadEncoding(payload, event.Payload) {
		return nil, Source{}, errors.New("invalid payload encoding")
	}
	source, err := payloadSource(payload)
	return payload, source, err
}
