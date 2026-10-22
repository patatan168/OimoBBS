// 構文検査済みJSONの重複・Unicode・深さと保存型を同時に照合し、本文の再走査を省く。
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

type shapeField struct {
	typ   reflect.Type
	index int
}

type shapeFields struct {
	fields map[string]shapeField
	err    error
}

var fieldShapes sync.Map
var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// structShape は呼出元が指定した保存型の明示タグだけを共有し、入力本文を保持しない。
func structShape(t reflect.Type) *shapeFields {
	if found, ok := fieldShapes.Load(t); ok {
		return found.(*shapeFields)
	}
	meta := &shapeFields{fields: make(map[string]shapeField, t.NumField())}
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
		meta.fields[key] = shapeField{field.Type, i}
	}
	stored, _ := fieldShapes.LoadOrStore(t, meta)
	return stored.(*shapeFields)
}

// shapeScanner は一回の走査内だけ深さと型を保持し、復号後の入力は共有しない。
type shapeScanner struct {
	keyScanner
	depth int
}

// fieldSet は既知のstructフィールド番号で重複を検出する。256項目まで割当を避ける。
// それ以上の保存型も上限を追加せず、超過した番号だけmapへ保持する。
type fieldSet struct {
	small [4]uint64
	large map[int]struct{}
}

func (s *fieldSet) add(index int) bool {
	if index < 256 {
		mask := uint64(1) << (index % 64)
		word := &s.small[index/64]
		if *word&mask != 0 {
			return false
		}
		*word |= mask
		return true
	}
	if s.large == nil {
		s.large = make(map[int]struct{})
	}
	if _, exists := s.large[index]; exists {
		return false
	}
	s.large[index] = struct{}{}
	return true
}

// value はnullableと独自復号器を区別し、型ごとの追加制約だけを検査する。
func (s *shapeScanner) value(t reflect.Type) error {
	s.space()
	if t == rawType {
		return s.skipValue()
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
		return s.skipValue()
	}
	switch t.Kind() {
	case reflect.Struct:
		return s.object(t)
	case reflect.Slice, reflect.Array:
		return s.array(t)
	}
	start := s.pos
	if err := s.skipValue(); err != nil {
		return err
	}
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

// object はキーを保存型へ照合し、復号後の重複と必須フィールドの欠落を検出する。
func (s *shapeScanner) object(t reflect.Type) error {
	if s.body[s.pos] != '{' {
		return errors.New("object required for struct")
	}
	if s.depth == 16 {
		return errors.New("JSON depth")
	}
	s.depth++
	defer func() { s.depth-- }()
	meta := structShape(t)
	if meta.err != nil {
		return meta.err
	}
	s.pos++
	count := 0
	var seen fieldSet
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
		field, ok := meta.fields[string(key)]
		if !ok {
			return errors.New("missing or unknown key")
		}
		if !seen.add(field.index) {
			return errors.New("duplicate or invalid key")
		}
		count++
		s.space()
		s.pos++ // colon
		if err := s.value(field.typ); err != nil {
			return fmt.Errorf("%s: %w", string(key), err)
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
	if s.depth == 16 {
		return errors.New("JSON depth")
	}
	s.depth++
	defer func() { s.depth-- }()
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

// skipValue はRawMessage・map・独自復号器にも重複・Unicode・深さの検査を適用する。
func (s *shapeScanner) skipValue() error {
	switch s.body[s.pos] {
	case '{', '[':
		return s.container(s.depth + 1)
	case '"':
		_, err := s.quoted(false)
		return err
	}
	for s.pos < len(s.body) {
		switch s.body[s.pos] {
		case ',', '}', ']', ' ', '\t', '\r', '\n':
			return nil
		}
		s.pos++
	}
	return nil
}
