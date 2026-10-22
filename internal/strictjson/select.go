// JSON全体の厳密検査と、必要な最上位フィールドの元byte参照を一度の走査で行う。
package strictjson

import "encoding/json"

// SelectFields は本文全体をValidateと同じ条件で検査し、指定キーの値だけを返す。
// キーは復号後の完全一致で照合し、欠落値はnil。不正な本文はmapを返さない。
// 値はbを参照するため、使用中はbを変更せず、必要なら呼出元で複製する。
func SelectFields(b []byte, names ...string) (map[string]json.RawMessage, error) {
	fields := make(map[string]json.RawMessage, len(names))
	for _, name := range names {
		fields[name] = nil
	}
	if err := validateFields(b, fields); err != nil {
		return nil, err
	}
	return fields, nil
}
