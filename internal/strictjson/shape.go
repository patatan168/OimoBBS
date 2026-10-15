// 構文・重複・Unicodeを検証済みのJSONを複製せず、保存型の必須キーとnull・数値を照合する。
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

type shapeFields struct {
	fields map[string]reflect.Type
	err    error
}

var fieldShapes sync.Map
var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// structShape は呼出元が指定した保存型の明示タグだけを共有し、入力本文を保持しない。
func structShape(t reflect.Type) *shapeFields {
	if found, ok := fieldShapes.Load(t); ok {
		return found.(*shapeFields)
	}
	meta := &shapeFields{fields: make(map[string]reflect.Type, t.NumField())}
	for i := range t.NumField() {
		field := t.Field(i)
		key, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if key == "" || key == "-" {
			meta.err = errors.New("explicit JSON field tags required")
			break
		}
		if _, exists := meta.fields[key]; exists {
			meta.err = errors.New("ambiguous JSON field tags")
			break
		}
		meta.fields[key] = field.Type
	}
	stored, _ := fieldShapes.LoadOrStore(t, meta)
	return stored.(*shapeFields)
}

// shape はValidateを通過した本文専用。構文検査と最後のjson.Unmarshalを省略しない。
func shape(body []byte, t reflect.Type) error {
	s := shapeScanner{keyScanner{body: body}}
	return s.value(t)
}

type shapeScanner struct{ keyScanner }

// value はnullableと独自復号器を区別し、型ごとの追加制約だけを検査する。
func (s *shapeScanner) value(t reflect.Type) error {
	s.space()
	if t == rawType {
		s.skip()
		return nil
	}
	if s.body[s.pos] == 'n' {
		if t.Kind() != reflect.Pointer {
			return errors.New("unexpected null")
		}
		s.pos += 4
		return nil
	}
	if t.Kind() == reflect.Pointer {
		return s.value(t.Elem())
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		s.skip()
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		return s.object(t)
	case reflect.Slice, reflect.Array:
		return s.array(t)
	}
	start := s.pos
	s.skip()
	value := s.body[start:s.pos]
	switch t.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if value[0] == '-' || bytes.ContainsAny(value, ".eE+") {
			return errors.New("unsigned integer required")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if bytes.Equal(value, []byte("-0")) || bytes.ContainsAny(value, ".eE+") {
			return errors.New("canonical integer required")
		}
	}
	return nil
}

// object は重複拒否済みのキーを保存型へ照合し、必須フィールドの欠落を件数で検出する。
func (s *shapeScanner) object(t reflect.Type) error {
	if s.body[s.pos] != '{' {
		return errors.New("object required for struct")
	}
	meta := structShape(t)
	if meta.err != nil {
		return meta.err
	}
	s.pos++
	count := 0
	for {
		s.space()
		if s.body[s.pos] == '}' {
			s.pos++
			if count != len(meta.fields) {
				return errors.New("missing or unknown key")
			}
			return nil
		}
		key, err := s.quoted(true)
		if err != nil {
			return err
		}
		field, ok := meta.fields[key]
		if !ok {
			return errors.New("missing or unknown key")
		}
		count++
		s.space()
		s.pos++ // colon
		if err := s.value(field); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		s.space()
		if s.body[s.pos] == ',' {
			s.pos++
		}
	}
}

// array は要素を直接照合し、固定長配列だけ要素数も検査する。
func (s *shapeScanner) array(t reflect.Type) error {
	if s.body[s.pos] != '[' {
		return errors.New("array required")
	}
	s.pos++
	count := 0
	for {
		s.space()
		if s.body[s.pos] == ']' {
			s.pos++
			if t.Kind() == reflect.Array && count != t.Len() {
				return errors.New("array length")
			}
			return nil
		}
		if err := s.value(t.Elem()); err != nil {
			return err
		}
		count++
		s.space()
		if s.body[s.pos] == ',' {
			s.pos++
		}
	}
}

// skip は検証済みの値を読み飛ばす。RawMessageや独自復号器の本文を複製しない。
func (s *shapeScanner) skip() {
	if s.body[s.pos] == '"' {
		s.skipString()
		return
	}
	depth := 0
	for s.pos < len(s.body) {
		switch s.body[s.pos] {
		case '"':
			s.skipString()
			continue
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				return
			}
			depth--
			s.pos++
			if depth == 0 {
				return
			}
			continue
		case ',', ' ', '\t', '\r', '\n':
			if depth == 0 {
				return
			}
		}
		s.pos++
	}
}

// skipString は構文・Unicode検証済みの引用文字列だけを、escapeを復号せず通過する。
func (s *shapeScanner) skipString() {
	s.pos++
	end := s.pos + bytes.IndexByte(s.body[s.pos:], '"')
	if bytes.IndexByte(s.body[s.pos:end], '\\') < 0 {
		s.pos = end + 1
		return
	}
	for s.body[s.pos] != '"' {
		if s.body[s.pos] == '\\' {
			s.pos++
		}
		s.pos++
	}
	s.pos++
}
