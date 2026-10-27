// 所有列で同じ板設定を毎要求復号せず、revisionと元byteが一致する間だけ共有する。
package bootstrap

import (
	"bytes"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

type postingFormSettings struct {
	revision domain.U64
	raw      []byte
	value    boardValue
}

// postingFormSettings は現用行を毎回照合し、更新・破損・欠落時は必ず再検証する。
// 所有ワーカー専用。返す設定のslice・pointerを変更してはならない。
func (b *postingBoard) postingFormSettings() (boardValue, error) {
	row := b.control.State().Rows["board:state"]
	if cached := b.formSettings; cached != nil && cached.revision == row.Revision && bytes.Equal(cached.raw, row.Value) {
		return cached.value, nil
	}
	var value boardValue
	if err := strictjson.Decode(row.Value, &value); err != nil {
		return value, err
	}
	b.formSettings = &postingFormSettings{row.Revision, bytes.Clone(row.Value), value}
	return value, nil
}
