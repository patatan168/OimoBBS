// 現行保存JSONの全項目を出力し、選択なしの配列も明示する。
package disclosure

import (
	"encoding/json"
	"oimobbs/internal/strictjson"
)

// MarshalJSON は空配列を明示し、旧形式の項目省略を生成しない。
func (v Export) MarshalJSON() ([]byte, error) {
	type plain Export
	out := plain(v)
	if out.RejectedSources == nil {
		out.RejectedSources = nilSliceElement(out.RejectedSources)
	}
	return json.Marshal(out)
}

// UnmarshalJSON は完全型だけを読み、空の選択を内部表現へ戻す。
func (v *Export) UnmarshalJSON(raw []byte) error {
	type plain Export
	var next plain
	if err := strictjson.Decode(raw, &next); err != nil {
		return err
	}
	if len(next.RejectedSources) == 0 {
		next.RejectedSources = nil
	}
	*v = Export(next)
	return nil
}

// nilSliceElement は型を維持した空スライスを返す。
func nilSliceElement[T any](_ []T) []T { return []T{} }
