// 省略されたCAP専用フラグを補い、その他のキーを厳密に検査する。
package domain

import "oimobbs/internal/strictjson"

// UnmarshalJSON はCAP専用フラグのない記録を通常スレッドとして読み込む。
func (v *Policy) UnmarshalJSON(raw []byte) error {
	type wire Policy
	var decoded wire
	if err := strictjson.DecodeDefaultBool(raw, &decoded, "cap_only", false); err != nil {
		return err
	}
	*v = Policy(decoded)
	return nil
}
