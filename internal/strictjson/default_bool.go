// 省略可能なboolを補う際、本文全体のmap復号と再符号化を通常経路から除く。
package strictjson

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
)

// DecodeDefaultBool は最上位のnameが省略された場合だけ既定boolを補い、Decodeで厳密に復号する。
// name以外の必須項目・null・重複・未知キーは緩めない。dstは独自復号器を持たないwire型とする。
// 正規化後JSONのMaxBytesも従来のmap再符号化と同じ条件で検査し、入力本文は変更しない。
func DecodeDefaultBool(body []byte, dst any, name string, value bool) error {
	key, err := json.Marshal(name)
	if err != nil {
		return err
	}
	typ := reflect.TypeOf(dst)
	if name != "" && len(body) <= (MaxBytes-len(key)-7)/6 && typ != nil && typ.Kind() == reflect.Pointer && !reflect.ValueOf(dst).IsNil() {
		if handled, err := decodeCheckedDefault(body, reflect.ValueOf(dst).Elem(), MaxBytes, name, value); handled {
			return err
		}
	}
	selected, err := SelectFields(body, name)
	if err != nil {
		return err
	}
	// RawMessageのHTML escape等は最大6倍になる。上限へ届き得る大きい入力だけ
	// 元の正規化で長さを確定し、上限近傍の受理条件も変えない。
	if len(body) > (MaxBytes-len(key)-7)/6 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			return err
		}
		if _, ok := fields[name]; !ok {
			fields[name] = json.RawMessage(strconv.FormatBool(value))
		}
		normalized, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		return Decode(normalized, dst)
	}
	if selected[name] != nil {
		return Decode(body, dst)
	}
	start := bytes.IndexByte(body, '{') + 1 // SelectFieldsで最上位objectを検査済み。
	normalized := make([]byte, 0, len(body)+len(key)+7)
	normalized = append(normalized, body[:start]...)
	normalized = append(normalized, key...)
	normalized = append(normalized, ':')
	normalized = strconv.AppendBool(normalized, value)
	if bytes.TrimSpace(body[start:])[0] != '}' {
		normalized = append(normalized, ',')
	}
	normalized = append(normalized, body[start:]...)
	return Decode(normalized, dst)
}
