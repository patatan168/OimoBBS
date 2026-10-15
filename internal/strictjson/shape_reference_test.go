// 変更前の再帰復号と新しい型走査の受理条件・資源費用を比較する。
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

func referenceShape(b []byte, t reflect.Type) error {
	b = bytes.TrimSpace(b)
	if t == rawType {
		return nil
	} // タグ付きunionの呼出元が選択した型でもう一度検査する。
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(b, []byte("null")) {
			return nil
		}
		return referenceShape(b, t.Elem())
	}
	if bytes.Equal(b, []byte("null")) {
		return errors.New("unexpected null")
	}
	if reflect.PointerTo(t).Implements(reflect.TypeFor[json.Unmarshaler]()) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(b, &obj); err != nil {
			return err
		}
		if len(obj) != t.NumField() {
			return errors.New("missing or unknown key")
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			if key == "" || key == "-" {
				return errors.New("explicit JSON field tags required")
			}
			v, ok := obj[key]
			if !ok {
				return fmt.Errorf("missing key %s", key)
			}
			if err := referenceShape(v, f.Type); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	case reflect.Slice, reflect.Array:
		var vals []json.RawMessage
		if err := json.Unmarshal(b, &vals); err != nil {
			return err
		}
		if t.Kind() == reflect.Array && len(vals) != t.Len() {
			return errors.New("array length")
		}
		for _, v := range vals {
			if err := referenceShape(v, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		s := string(b)
		if len(s) == 0 || s[0] == '-' || strings.ContainsAny(s, ".eE+") {
			return errors.New("unsigned integer required")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if string(b) == "-0" || bytes.ContainsAny(b, ".eE+") {
			return errors.New("canonical integer required")
		}
	}
	return nil
}
