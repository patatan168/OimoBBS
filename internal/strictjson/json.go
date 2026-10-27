// Package strictjson は保存形式の重複キー・未知キー・不正Unicodeを拒否する。
package strictjson

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
)

const MaxBytes = 1 << 20

var rawType = reflect.TypeFor[json.RawMessage]()

// Validate は深さ16までの厳密なJSON objectを検査する。
func Validate(b []byte) error {
	return validateFields(b, nil)
}

// ValidateLimit は内部保存の明示上限でobjectを検証する。通常はValidateを使う。
func ValidateLimit(b []byte, limit int) error {
	_, err := checkedObject(b, limit, true, nil, nil)
	return err
}

func validateFields(b []byte, fields map[string]json.RawMessage) error {
	_, err := checkedObject(b, MaxBytes, true, fields, nil)
	return err
}

// objectScanner は構文・サイズ・UTF-8と最上位objectを検査し、本文を借りる走査器を返す。
func objectScanner(b []byte) (keyScanner, error) { return objectScannerLimit(b, MaxBytes) }

// objectScannerLimit は明示した保存経路だけで上限を拡張し、通常の入力上限は変えない。
func objectScannerLimit(b []byte, limit int) (keyScanner, error) {
	return checkedObject(b, limit, false, nil, nil)
}

// Decode は全structキーを必須・大小文字厳密として検査・復号する。nullableはポインタで表す。
func Decode(b []byte, dst any) error { return DecodeLimit(b, dst, MaxBytes) }

// DecodeLimit は有界の内部保存用。サイズ以外はDecodeと同じ厳密な型検査を行う。
func DecodeLimit(b []byte, dst any, limit int) error {
	if generated, ok := dst.(GeneratedDecoder); ok && reflect.TypeOf(dst) == generated.StrictJSONType() {
		if handled, err := generated.UnmarshalStrictJSON(b, limit); handled {
			return err
		}
	}
	typ := reflect.TypeOf(dst)
	if typ != nil && typ.Kind() == reflect.Pointer && !reflect.ValueOf(dst).IsNil() {
		if handled, err := decodeChecked(b, reflect.ValueOf(dst).Elem(), limit); handled {
			return err
		}
	}
	s, err := objectScannerLimit(b, limit)
	if err != nil {
		return err
	}
	if typ == nil || typ.Kind() != reflect.Pointer || reflect.ValueOf(dst).IsNil() {
		return errors.New("non-nil destination pointer required")
	}
	if err := (&shapeScanner{keyScanner: s}).value(typ.Elem()); err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}
func hex4(b []byte) (uint64, error) {
	if len(b) != 4 {
		return 0, errors.New("short unicode escape")
	}
	return strconv.ParseUint(string(b), 16, 16)
}
func unicodeEscapes(b []byte) error {
	in := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			in = !in
			continue
		}
		if !in {
			continue
		}
		if b[i] == 0 {
			return errors.New("NUL")
		}
		if b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return errors.New("short escape")
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return errors.New("short unicode escape")
		}
		n, err := hex4(b[i+1 : i+5])
		if err != nil {
			return err
		}
		i += 4
		if n == 0 || n >= 0xdc00 && n <= 0xdfff {
			return errors.New("NUL or isolated surrogate")
		}
		if n < 0xd800 || n > 0xdbff {
			continue
		}
		if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
			return errors.New("unpaired surrogate")
		}
		low, err := hex4(b[i+3 : i+7])
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return errors.New("invalid surrogate pair")
		}
		i += 6
	}
	return nil
}
