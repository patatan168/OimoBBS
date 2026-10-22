// 一回の一括追記内だけ、同じ完全payloadの業務検査結果を共有する。
package evidence

import (
	"bytes"
)

type preparedPayload struct {
	kind string
	raw  []byte
}

// validatePreparedPayload はsource/hash/署名の再検査後、同じ元byteの業務検査だけを再利用する。
// 内容・種別が異なる場合と再起動時は通常の完全検査を行う。WALの検査と耐久境界は省略しない。
func (j *Journal) validatePreparedPayload(event Event, raw []byte) error {
	if known, ok := j.preparedPayloads[event.PayloadSHA]; ok && known.kind == event.Kind && bytes.Equal(known.raw, raw) {
		return nil
	}
	return j.validatePayload(event.Kind, raw)
}
