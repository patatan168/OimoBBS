// 構文・型・重複キーを一度に照合し、独自復号器は本文全体の検査成功後に呼び出す。
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strconv"
	"unicode/utf8"
)

// decodeAction は検査済みの元byteと非公開の復号先だけを、この呼出し内で保持する。
type decodeAction struct {
	raw    []byte
	value  reflect.Value
	custom bool
}

type decodeActionGroup struct {
	before  int
	decoder *checkedDecoder
}

type checkedDecoder struct {
	checkedScanner
	depth        int
	local        [64]decodeAction
	count        int
	extra        []decodeAction
	groups       []decodeActionGroup
	defaultIndex int
	defaultValue bool
	workers      int
}

// decodeChecked はゼロ値の対応型を一走査で復号し、構文エラーで独自復号器を起動しない。
// 既存値のmerge・特殊タグは従来経路へ残し、失敗した候補を呼出元へ公開しない。
func decodeChecked(body []byte, dst reflect.Value, limit int) (bool, error) {
	return decodeCheckedDefault(body, dst, limit, "", false)
}

// decodeCheckedDefault は通常サイズの省略可能boolも同じ型付き走査で補う。
func decodeCheckedDefault(body []byte, dst reflect.Value, limit int, name string, value bool) (bool, error) {
	return decodeCheckedMode(body, dst, limit, name, value, false)
}

// decodeCheckedMode は一件内の分担可否を固定し、worker内の再帰的な起動を防ぐ。
func decodeCheckedMode(body []byte, dst reflect.Value, limit int, name string, value, serial bool) (bool, error) {
	if !dst.IsZero() {
		return false, nil
	}
	p := planFor(dst.Type())
	if !p.eligible {
		return false, nil
	}
	index := -1
	if name != "" {
		field, ok := p.fields[name]
		if !ok || field.plan.typ.Kind() != reflect.Bool || field.plan.custom || p.custom {
			return false, nil
		}
		index = field.index
	}
	if limit < 0 || limit > 8<<20 || len(body) > limit || !utf8.Valid(body) {
		return true, errors.New("JSON size or UTF-8")
	}
	workers := 1
	if !serial && len(body) >= 128<<10 {
		workers = runtime.GOMAXPROCS(0)
	}
	d := checkedDecoder{checkedScanner: checkedScanner{keyScanner: keyScanner{body: body}, strict: true}, defaultIndex: index, defaultValue: value, workers: workers}
	d.space()
	if d.pos == len(body) || body[d.pos] != '{' {
		return true, errSyntax
	}
	candidate := reflect.New(dst.Type()).Elem()
	if err := d.value(p, candidate); err != nil {
		return true, err
	}
	d.space()
	if d.pos != len(body) {
		return true, errSyntax
	}
	if err := d.runActions(); err != nil {
		return true, err
	}
	dst.Set(candidate)
	return true, nil
}

// runActions は全体の検査成功後だけ、独自復号を元の順序で逐次実行する。
// 分担先の保留領域は複製せず、親のaction間に挿入して保持量を抑える。
func (d *checkedDecoder) runActions() error {
	group := 0
	for i := 0; i <= d.count; i++ {
		for group < len(d.groups) && d.groups[group].before == i {
			if err := d.groups[group].decoder.runActions(); err != nil {
				return err
			}
			group++
		}
		if i == d.count {
			break
		}
		action := d.action(i)
		var err error
		if action.custom {
			err = action.value.Addr().Interface().(json.Unmarshaler).UnmarshalJSON(action.raw)
		} else {
			err = json.Unmarshal(action.raw, action.value.Addr().Interface())
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// value は未知形式の値にも同じ深さ・Unicode・重複キー制約を適用する。
func (d *checkedDecoder) value(p *decodePlan, v reflect.Value) error {
	d.space()
	if d.pos == len(d.body) {
		return errSyntax
	}
	if p.typ == rawType {
		start := d.pos
		if err := d.checkedValue(d.depth); err != nil {
			return err
		}
		v.SetBytes(bytes.Clone(d.body[start:d.pos]))
		return nil
	}
	if d.body[d.pos] == 'n' {
		if p.typ.Kind() != reflect.Pointer {
			return errors.New("unexpected null")
		}
		return d.checkedLiteral("null")
	}
	if p.typ.Kind() == reflect.Pointer {
		v.Set(reflect.New(p.typ.Elem()))
		return d.value(p.elem, v.Elem())
	}
	if p.custom {
		return d.deferValue(v, true)
	}
	switch p.typ.Kind() {
	case reflect.Struct:
		return d.object(p, v)
	case reflect.Array, reflect.Slice:
		return d.array(p, v)
	case reflect.String:
		text, err := d.checkedString(true)
		if err == nil {
			v.SetString(string(text))
		}
		return err
	case reflect.Bool:
		switch d.body[d.pos] {
		case 't':
			if err := d.checkedLiteral("true"); err != nil {
				return err
			}
			v.SetBool(true)
			return nil
		case 'f':
			return d.checkedLiteral("false")
		}
		return errors.New("boolean required")
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return d.integer(p, v)
	}
	return d.deferValue(v, false)
}

// deferValue は任意の復号器を実行する前に、元byte全体の構文と厳密制約を確定する。
func (d *checkedDecoder) deferValue(v reflect.Value, custom bool) error {
	start := d.pos
	if err := d.checkedValue(d.depth); err != nil {
		return err
	}
	d.addAction(decodeAction{d.body[start:d.pos], v, custom})
	return nil
}

// addAction は独自復号の実行順を元のJSON順に保つ。
func (d *checkedDecoder) addAction(action decodeAction) {
	if d.count < len(d.local) {
		d.local[d.count] = action
	} else {
		d.extra = append(d.extra, action)
	}
	d.count++
}

func (d *checkedDecoder) action(i int) decodeAction {
	if i < len(d.local) {
		return d.local[i]
	}
	return d.extra[i-len(d.local)]
}

func (d *checkedDecoder) integer(p *decodePlan, v reflect.Value) error {
	start := d.pos
	if err := d.checkedNumber(); err != nil {
		return err
	}
	raw := d.body[start:d.pos]
	if bytes.ContainsAny(raw, ".eE+") {
		return errors.New("canonical integer required")
	}
	if p.typ.Kind() >= reflect.Uint && p.typ.Kind() <= reflect.Uint64 {
		n, err := strconv.ParseUint(string(raw), 10, p.typ.Bits())
		if err != nil {
			return err
		}
		v.SetUint(n)
		return nil
	}
	if bytes.Equal(raw, []byte("-0")) {
		return errors.New("canonical integer required")
	}
	n, err := strconv.ParseInt(string(raw), 10, p.typ.Bits())
	if err == nil {
		v.SetInt(n)
	}
	return err
}

func (d *checkedDecoder) object(p *decodePlan, v reflect.Value) error {
	if d.body[d.pos] != '{' || d.depth == 16 {
		return errSyntax
	}
	d.depth++
	defer func() { d.depth-- }()
	d.pos++
	d.space()
	count := 0
	var seen fieldSet
	if d.pos < len(d.body) && d.body[d.pos] == '}' {
		d.pos++
		return d.completeObject(p, v, count, &seen)
	}
	for {
		key, err := d.checkedString(true)
		if err != nil {
			return err
		}
		field, ok := p.fields[string(key)]
		if !ok || !seen.add(field.index) {
			return errors.New("duplicate or unknown key")
		}
		count++
		d.space()
		if d.pos == len(d.body) || d.body[d.pos] != ':' {
			return errSyntax
		}
		d.pos++
		if err := d.value(field.plan, v.Field(field.index)); err != nil {
			return err
		}
		end, err := d.separator('}')
		if err != nil {
			return err
		}
		if end {
			return d.completeObject(p, v, count, &seen)
		}
	}
}

// completeObject は指定された最上位bool一項目だけを補い、他の必須キーは緩めない。
func (d *checkedDecoder) completeObject(p *decodePlan, v reflect.Value, count int, seen *fieldSet) error {
	if count == len(p.fields) {
		return nil
	}
	if d.depth == 1 && d.defaultIndex >= 0 && count+1 == len(p.fields) && seen.add(d.defaultIndex) {
		v.Field(d.defaultIndex).SetBool(d.defaultValue)
		return nil
	}
	return errors.New("missing or unknown key")
}

func (d *checkedDecoder) array(p *decodePlan, v reflect.Value) error {
	if d.body[d.pos] != '[' || d.depth == 16 {
		return errSyntax
	}
	d.depth++
	defer func() { d.depth-- }()
	d.pos++
	d.space()
	count := 0
	if p.typ.Kind() == reflect.Slice {
		length, spans, err := d.arrayLayout()
		if err != nil {
			return err
		}
		// 独自復号の保留中にGrowで要素の保存先が移動しないよう、一度だけ確保する。
		v.Set(reflect.MakeSlice(p.typ, length, length))
		if len(spans) > 1 {
			if handled, err := d.decodeArrayParallel(p, v, spans); handled {
				return err
			}
		}
	}
	if d.pos < len(d.body) && d.body[d.pos] == ']' {
		d.pos++
		if p.typ.Kind() == reflect.Array && v.Len() != 0 {
			return errors.New("array length")
		}
		return nil
	}
	for {
		if count == v.Len() {
			return errors.New("array length")
		}
		if err := d.value(p.elem, v.Index(count)); err != nil {
			return err
		}
		count++
		end, err := d.separator(']')
		if err != nil {
			return err
		}
		if end {
			if p.typ.Kind() == reflect.Array && count != v.Len() {
				return errors.New("array length")
			}
			return nil
		}
	}
}

// separator は値の直後の区切りだけを処理し、末尾commaは次の値検査で拒否する。
func (d *keyScanner) separator(close byte) (bool, error) {
	d.space()
	if d.pos == len(d.body) {
		return false, errSyntax
	}
	c := d.body[d.pos]
	if c != close && c != ',' {
		return false, errSyntax
	}
	d.pos++
	d.space()
	return c == close, nil
}
