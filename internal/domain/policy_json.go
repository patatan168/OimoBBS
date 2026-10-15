// 旧保存形式で省略されたCAP専用フラグを補い、その他のキーは厳密に検査する。
package domain

import (
	"encoding/json"
	"oimobbs/internal/strictjson"
)

// UnmarshalJSON はCAP専用フラグのない旧記録を通常スレッドとして読み込む。
func (v *Policy) UnmarshalJSON(raw []byte) error {
	if err := strictjson.Validate(raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if _, ok := fields["cap_only"]; !ok {
		fields["cap_only"] = json.RawMessage("false")
	}
	normalized, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	type wire Policy
	var decoded wire
	if err := strictjson.Decode(normalized, &decoded); err != nil {
		return err
	}
	*v = Policy(decoded)
	return nil
}
