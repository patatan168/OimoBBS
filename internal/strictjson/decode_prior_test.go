// 構文検査済みJSONの型制約・Unicode・重複を照合しながら、非公開の候補へ復号する。
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
)

type valueDecoder struct {
	shapeScanner
}

// decodeFresh はゼロ値の保存DTOだけを対象とし、失敗した候補を呼出元へ反映しない。
// 既存mapのmergeや独自復号器の既存状態が必要な復号は従来経路へ残す。
func decodeFresh(s keyScanner, dst reflect.Value) (bool, error) {
	if !dst.IsZero() {
		return false, nil
	}
	plan := planFor(dst.Type())
	if !plan.eligible {
		return false, nil
	}
	candidate := reflect.New(dst.Type()).Elem()
	d := valueDecoder{shapeScanner: shapeScanner{keyScanner: s}}
	if err := d.decode(plan, candidate); err != nil {
		return true, err
	}
	dst.Set(candidate)
	return true, nil
}

func (d *valueDecoder) decode(p *decodePlan, v reflect.Value) error {
	d.space()
	if p.typ == rawType {
		start := d.pos
		if err := d.skipValue(); err != nil {
			return err
		}
		v.SetBytes(bytes.Clone(d.body[start:d.pos]))
		return nil
	}
	if d.body[d.pos] == 'n' {
		if p.typ.Kind() != reflect.Pointer {
			return errors.New("unexpected null")
		}
		d.pos += 4
		return nil
	}
	if p.typ.Kind() == reflect.Pointer {
		v.Set(reflect.New(p.typ.Elem()))
		return d.decode(p.elem, v.Elem())
	}
	if p.custom {
		start := d.pos
		if err := d.skipValue(); err != nil {
			return err
		}
		return v.Addr().Interface().(json.Unmarshaler).UnmarshalJSON(d.body[start:d.pos])
	}
	switch p.typ.Kind() {
	case reflect.Struct:
		return d.objectValue(p, v)
	case reflect.Array, reflect.Slice:
		return d.arrayValue(p, v)
	case reflect.String:
		if d.body[d.pos] != '"' {
			return errors.New("string required")
		}
		text, err := d.quoted(true)
		if err == nil {
			v.SetString(string(text))
		}
		return err
	case reflect.Bool:
		switch d.body[d.pos] {
		case 't':
			v.SetBool(true)
			d.pos += 4
			return nil
		case 'f':
			d.pos += 5
			return nil
		}
		return errors.New("boolean required")
	}
	return d.scalarValue(p, v)
}

func (d *valueDecoder) scalarValue(p *decodePlan, v reflect.Value) error {
	start := d.pos
	if err := d.skipValue(); err != nil {
		return err
	}
	raw := d.body[start:d.pos]
	switch p.typ.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if raw[0] == '-' || bytes.ContainsAny(raw, ".eE+") {
			return errors.New("unsigned integer required")
		}
		n, err := strconv.ParseUint(string(raw), 10, p.typ.Bits())
		if err != nil {
			return err
		}
		v.SetUint(n)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if bytes.Equal(raw, []byte("-0")) || bytes.ContainsAny(raw, ".eE+") {
			return errors.New("canonical integer required")
		}
		n, err := strconv.ParseInt(string(raw), 10, p.typ.Bits())
		if err != nil {
			return err
		}
		v.SetInt(n)
		return nil
	}
	// map・interface等は、従来のshape検査と標準復号の組合せを維持する。
	return json.Unmarshal(raw, v.Addr().Interface())
}

func (d *valueDecoder) objectValue(p *decodePlan, v reflect.Value) error {
	if d.body[d.pos] != '{' {
		return errors.New("object required for struct")
	}
	if d.depth == 16 {
		return errors.New("JSON depth")
	}
	d.depth++
	defer func() { d.depth-- }()
	d.pos++
	count := 0
	var seen fieldSet
	for {
		d.space()
		if d.body[d.pos] == '}' {
			d.pos++
			if count != len(p.fields) {
				return errors.New("missing or unknown key")
			}
			return nil
		}
		key, err := d.quoted(true)
		if err != nil {
			return err
		}
		field, ok := p.fields[string(key)]
		if !ok {
			return errors.New("missing or unknown key")
		}
		if !seen.add(field.index) {
			return errors.New("duplicate or invalid key")
		}
		count++
		d.space()
		d.pos++
		if err := d.decode(field.plan, v.Field(field.index)); err != nil {
			return err
		}
		d.space()
		if d.body[d.pos] == ',' {
			d.pos++
		}
	}
}

func (d *valueDecoder) arrayValue(p *decodePlan, v reflect.Value) error {
	if d.body[d.pos] != '[' {
		return errors.New("array required")
	}
	if d.depth == 16 {
		return errors.New("JSON depth")
	}
	d.depth++
	defer func() { d.depth-- }()
	d.pos++
	count := 0
	if p.typ.Kind() == reflect.Slice {
		v.Set(reflect.MakeSlice(p.typ, 0, 0))
	}
	for {
		d.space()
		if d.body[d.pos] == ']' {
			d.pos++
			if p.typ.Kind() == reflect.Array && count != v.Len() {
				return errors.New("array length")
			}
			return nil
		}
		if p.typ.Kind() == reflect.Slice {
			v.Grow(1)
			v.SetLen(count + 1)
		} else if count == v.Len() {
			return errors.New("array length")
		}
		if err := d.decode(p.elem, v.Index(count)); err != nil {
			return err
		}
		count++
		d.space()
		if d.body[d.pos] == ',' {
			d.pos++
		}
	}
}
