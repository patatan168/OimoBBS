// 生成復号と変更前の反射復号を、実保存型の構造・変異・merge・入力所有権で比較する。
package strictjson_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type priorOperation domain.Operation
type priorAppend domain.Append
type priorCreate domain.Create
type priorObservation evidence.HTTPObservation
type priorEvent evidence.Event
type priorOptionalRecord evidence.OptionalRecord
type priorOptionalPayload evidence.OptionalPayload
type priorCapture postcapture.Capture
type priorControl store.ControlOperation

type target struct {
	name           string
	current, prior func() any
}

var targets = []target{
	{"operation", func() any { return new(domain.Operation) }, func() any { return new(priorOperation) }},
	{"append", func() any { return new(domain.Append) }, func() any { return new(priorAppend) }},
	{"create", func() any { return new(domain.Create) }, func() any { return new(priorCreate) }},
	{"observation", func() any { return new(evidence.HTTPObservation) }, func() any { return new(priorObservation) }},
	{"event", func() any { return new(evidence.Event) }, func() any { return new(priorEvent) }},
	{"optional_record", func() any { return new(evidence.OptionalRecord) }, func() any { return new(priorOptionalRecord) }},
	{"optional_payload", func() any { return new(evidence.OptionalPayload) }, func() any { return new(priorOptionalPayload) }},
	{"capture", func() any { return new(postcapture.Capture) }, func() any { return new(priorCapture) }},
	{"control", func() any { return new(store.ControlOperation) }, func() any { return new(priorControl) }},
}

// populate は業務判定から独立した、完全型として読める保存値を作る。
// 独自スカラーは標準Marshalへ通し、期待JSONを新しいreaderで作らない。
func populate(v reflect.Value, full bool) {
	if v.Type() == reflect.TypeFor[json.RawMessage]() {
		v.SetBytes([]byte(`{"opaque":[null,{"v":1}]}`))
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if full {
			v.Set(reflect.New(v.Type().Elem()))
			populate(v.Elem(), full)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			populate(v.Field(i), full)
		}
	case reflect.Slice:
		count := 0
		if full {
			count = 2
		}
		v.Set(reflect.MakeSlice(v.Type(), count, count))
		for i := 0; i < count; i++ {
			populate(v.Index(i), full)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			populate(v.Index(i), full)
		}
	case reflect.String:
		v.SetString("日本語😀<&>\n\"text\\")
	case reflect.Bool:
		v.SetBool(full)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(42)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(-42)
	default:
		panic(v.Type().String())
	}
}

func fixture(t testing.TB, tc target, full bool) []byte {
	t.Helper()
	v := tc.current()
	populate(reflect.ValueOf(v).Elem(), full)
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func compare(t testing.TB, tc target, raw []byte, limit int, initial []byte) {
	t.Helper()
	want, got := tc.prior(), tc.current()
	if initial != nil {
		if err := strictjson.Decode(initial, want); err != nil {
			t.Fatal(err)
		}
		if err := strictjson.Decode(initial, got); err != nil {
			t.Fatal(err)
		}
	}
	oe, ge := strictjson.DecodeLimit(raw, want, limit), strictjson.DecodeLimit(raw, got, limit)
	expected := reflect.ValueOf(want).Elem().Convert(reflect.TypeOf(got).Elem()).Interface()
	if (oe == nil) != (ge == nil) || oe == nil && !reflect.DeepEqual(expected, reflect.ValueOf(got).Elem().Interface()) {
		t.Fatalf("%s differs: prior=%v typed=%v input=%q", tc.name, oe, ge, raw)
	}
	if ge != nil && initial == nil && !reflect.ValueOf(got).Elem().IsZero() {
		t.Fatalf("%s exposed rejected candidate", tc.name)
	}
	if ge == nil {
		owned := bytes.Clone(raw)
		value := tc.current()
		if err := strictjson.DecodeLimit(owned, value, limit); err != nil {
			t.Fatal(err)
		}
		for i := range owned {
			owned[i] = 0
		}
		if !reflect.DeepEqual(reflect.ValueOf(value).Elem().Interface(), reflect.ValueOf(got).Elem().Interface()) {
			t.Fatal("borrowed input retained")
		}
	}
}

func TestGeneratedDecodeEquivalence(t *testing.T) {
	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			for _, full := range []bool{false, true} {
				raw := fixture(t, tc, full)
				compare(t, tc, raw, strictjson.MaxBytes, nil)
				compare(t, tc, raw, strictjson.MaxBytes, raw)
				for _, limit := range []int{-1, len(raw) - 1, len(raw), 8<<20 + 1} {
					compare(t, tc, raw, limit, nil)
				}
				for _, size := range []int{(128 << 10) - 1, 128 << 10, (128 << 10) + 1} {
					padded := append(bytes.Repeat([]byte{' '}, size-len(raw)), raw...)
					compare(t, tc, padded, strictjson.MaxBytes, nil)
				}
				for i := 0; i < len(raw); i += max(1, len(raw)/100) {
					compare(t, tc, raw[:i], strictjson.MaxBytes, nil)
					for _, c := range []byte{0, 0xff, '"', '\\', ',', '}', ']', '0'} {
						changed := bytes.Clone(raw)
						changed[i] = c
						compare(t, tc, changed, strictjson.MaxBytes, nil)
					}
				}
				for _, prefix := range []string{`"extra":null,`, `"\u0065xtra":null,`} {
					compare(t, tc, append([]byte("{"+prefix), raw[1:]...), strictjson.MaxBytes, nil)
				}
				compare(t, tc, append(bytes.Clone(raw), 'x'), strictjson.MaxBytes, nil)
			}
		})
	}
}

func TestGeneratedMethodPromotionAndNil(t *testing.T) {
	var value *domain.Append
	if strictjson.Decode([]byte(`{"posts":[]}`), value) == nil {
		t.Fatal("nil destination")
	}
	type wrapper struct {
		domain.Append `json:"nested"`
	}
	var got wrapper
	if err := strictjson.Decode([]byte(`{"nested":{"posts":[]}}`), &got); err != nil || got.Posts == nil {
		t.Fatal("promoted method selected", err)
	}
}

func TestGeneratedCustomScalarCompatibility(t *testing.T) {
	raw := fixture(t, targets[7], true)
	for _, change := range [][2]string{
		{`"42"`, `"\u0034\u0032"`}, {`"-42"`, `"\u002d42"`},
		{`"42"`, `"18446744073709551615"`}, {`"42"`, `"18446744073709551616"`},
		{`"-42"`, `"-9223372036854775808"`}, {`"-42"`, `"-9223372036854775809"`},
		{`"42"`, `"+42"`}, {`"-42"`, `"-0"`}, {`"42"`, `"042"`},
		{`"cap_only":true,`, ``}, {`"cap_only":true`, `"cap_only":null`},
		{`"cap_only":true`, `"cap_only":false,"cap_only":true`},
		{`"token":`, `"Token":`}, {`"token":`, `"\u0074oken":`},
	} {
		compare(t, targets[7], bytes.ReplaceAll(raw, []byte(change[0]), []byte(change[1])), strictjson.MaxBytes, nil)
	}
	for _, tc := range targets {
		for _, raw := range []string{`{}`, `null`, `[]`, `{"opaque":"\ud800"}`, `{"opaque":"\u0000"}`, `{"x":0,"x":1}`, `{"x":` + strings.Repeat("[", 16) + `0` + strings.Repeat("]", 16) + `}`} {
			compare(t, tc, []byte(raw), strictjson.MaxBytes, nil)
		}
	}
}

func FuzzGeneratedDecode(f *testing.F) {
	for _, tc := range targets {
		f.Add(fixture(f, tc, true))
	}
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, tc := range targets {
			compare(t, tc, raw, strictjson.MaxBytes, nil)
		}
	})
}

func FuzzGeneratedMutation(f *testing.F) {
	bodies := make([][]byte, len(targets))
	for i, tc := range targets {
		bodies[i] = fixture(f, tc, true)
		f.Add(byte(i), uint16(0), byte('{'), byte(0))
	}
	f.Fuzz(func(t *testing.T, which byte, offset uint16, value, mode byte) {
		i := int(which) % len(targets)
		raw := bytes.Clone(bodies[i])
		index := int(offset) % len(raw)
		switch mode % 3 {
		case 0:
			raw[index] = value
		case 1:
			raw = append(raw[:index:index], append([]byte{value}, raw[index:]...)...)
		case 2:
			raw = append(raw[:index], raw[index+1:]...)
		}
		compare(t, targets[i], raw, strictjson.MaxBytes, nil)
	})
}

// replaceValues は構造を保った正しいJSONで、文字列・整数端・省略boolを同時に変える。
func replaceValues(v reflect.Value, text string, number uint64, flag bool) {
	if v.Type() == reflect.TypeFor[json.RawMessage]() {
		raw, _ := json.Marshal(map[string]string{"text": text})
		v.SetBytes(raw)
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			replaceValues(v.Elem(), text, number, flag)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			replaceValues(v.Field(i), text, number, flag)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			replaceValues(v.Index(i), text, number, flag)
		}
	case reflect.Array: // ID/Hashは常に非ゼロの固定fixtureを維持する。
	case reflect.String:
		v.SetString(text)
	case reflect.Bool:
		v.SetBool(flag)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(number)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(number))
	}
}

func FuzzGeneratedValues(f *testing.F) {
	f.Add(byte(0), "日本語😀<&>\n", uint64(42), true)
	f.Add(byte(7), "", ^uint64(0), false)
	f.Fuzz(func(t *testing.T, which byte, text string, number uint64, flag bool) {
		if len(text) > 1024 {
			text = text[:1024]
		}
		tc := targets[int(which)%len(targets)]
		v := tc.current()
		populate(reflect.ValueOf(v).Elem(), true)
		replaceValues(reflect.ValueOf(v).Elem(), text, number, flag)
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		compare(t, tc, raw, strictjson.MaxBytes, nil)
	})
}

func BenchmarkGeneratedDecode(b *testing.B) {
	for _, tc := range targets {
		raw := fixture(b, tc, true)
		for _, version := range []struct {
			name     string
			newValue func() any
		}{{"prior", tc.prior}, {"typed", tc.current}} {
			b.Run(tc.name+"/"+version.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if err := strictjson.Decode(raw, version.newValue()); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
