// 省略されたCAP専用フラグを補い、その他のキーを厳密に検査する。
package postinput

import "oimobbs/internal/strictjson"

// UnmarshalJSON はCAP専用フラグのない記録を通常スレッドとして読み込む。
func (v *Input) UnmarshalJSON(raw []byte) error {
	type wire Input
	var decoded wire
	if err := strictjson.DecodeDefaultBool(raw, &decoded, "cap_only", false); err != nil {
		return err
	}
	*v = Input(decoded)
	return nil
}
