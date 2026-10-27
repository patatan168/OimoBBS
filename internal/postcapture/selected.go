// 正常な現行captureは完全復号で種別も確定し、別形式だけ従来のschema判別へ戻す。
package postcapture

// decodeSelected は完全型・業務制約を満たす現行形式を一度で復号する。
// 失敗時は従来の種別判別を行い、未知形式の委譲、重複schemaの選択、
// 不正入力の拒否を維持する。復号候補は呼出し内だけに保持する。
func decodeSelected(raw []byte) (decodedCapture, string, error) {
	c, decodeErr := decode(raw)
	if decodeErr == nil {
		return c, Schema, nil
	}
	schema, err := schemaOf(raw)
	if err != nil || schema != Schema {
		return decodedCapture{}, schema, err
	}
	return c, schema, decodeErr
}
