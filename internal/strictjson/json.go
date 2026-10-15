// Package strictjson は保存形式の重複キー・未知キー・不正Unicodeを拒否する。
package strictjson

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"unicode/utf8"
)

const MaxBytes = 1 << 20

var rawType = reflect.TypeFor[json.RawMessage]()

// Validate は深さ16までの厳密なJSON objectを検査する。
func Validate(b []byte) error {
	if len(b) > MaxBytes || !utf8.Valid(b) {
		return errors.New("JSON size or UTF-8")
	}
	if !json.Valid(b) {
		return errors.New("invalid JSON")
	}
	s := keyScanner{body: b}
	s.space()
	if s.body[s.pos] != '{' {
		return errors.New("object required")
	}
	return s.container(1)
}

// Decode は全structキーを必須・大小文字厳密として検査後に復号する。nullableはポインタで表す。
func Decode(b []byte, dst any) error {
	if err := Validate(b); err != nil {
		return err
	}
	typ := reflect.TypeOf(dst)
	if typ == nil || typ.Kind() != reflect.Pointer || reflect.ValueOf(dst).IsNil() {
		return errors.New("non-nil destination pointer required")
	}
	if err := shape(b, typ.Elem()); err != nil {
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
