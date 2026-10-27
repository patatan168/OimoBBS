// 構文・厳密検証をまとめる走査を、従来の標準構文検査と独立に差分照合する。
package strictjson

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// legacyObjectScanner は変更前の構文境界を保ち、試作の走査器を参照しない。
func legacyObjectScanner(raw []byte) (keyScanner, error) {
	if len(raw) > MaxBytes || !utf8.Valid(raw) || !json.Valid(raw) {
		return keyScanner{}, errors.New("invalid JSON")
	}
	s := keyScanner{body: raw}
	s.space()
	if s.body[s.pos] != '{' {
		return s, errors.New("object required")
	}
	return s, nil
}
func legacyCheckedValidate(raw []byte) error {
	s, e := legacyObjectScanner(raw)
	if e != nil {
		return e
	}
	return s.container(1)
}
func legacyCheckedDecode(raw []byte, dst any) error {
	s, e := legacyObjectScanner(raw)
	if e != nil {
		return e
	}
	v := reflect.ValueOf(dst).Elem()
	if ok, e := decodeFresh(s, v); ok {
		return e
	}
	if e = (&shapeScanner{keyScanner: s}).value(v.Type()); e != nil {
		return e
	}
	return json.Unmarshal(raw, dst)
}
func checkChecked(t testing.TB, raw []byte) {
	t.Helper()
	old, now := legacyCheckedValidate(raw), Validate(raw)
	if (old == nil) != (now == nil) {
		t.Fatalf("validation changed %q: %v / %v", raw, old, now)
	}
	var a, b fusedRecord
	oe, ne := legacyCheckedDecode(raw, &a), Decode(raw, &b)
	if (oe == nil) != (ne == nil) || oe == nil && !reflect.DeepEqual(a, b) {
		t.Fatalf("decode changed %q: %v / %v", raw, oe, ne)
	}
}
func TestCheckedBoundaries(t *testing.T) {
	for _, raw := range []string{`{}`, ` {"a":[true,false,null,0,-0,1.25e-7]} `, `{"x":01}`, `{"x":-}`, `{"x":1.}`, `{"x":1e+}`, `{"x":1e2x}`, `{"x":tru}`, `{"x":truefalse}`, `{"x":0,}`, `{"x":[1,]}`, `{"x" 1}`, `{"x":}`, `{"x":[]]}`, `{"x":"\ud83d\ude00"}`, `{"x":"\ud83d"}`, `{"x":"\u0000"}`, `{"a":1,"\u0061":2}`, `{"x":"\\\""}`, `{"x":"\v"}`, `{"x":"unterminated}`, `{"x":1}{}`, `{"x":1}null`, "", " ", `[]`, string(fusedFixture())} {
		checkChecked(t, []byte(raw))
	}
	for _, n := range []int{0, 1, 7, 8, 15, 16, 31, 32, 128, 8192} {
		for b := 0; b < 256; b++ {
			raw := []byte(`{"x":"` + strings.Repeat("x", n) + string(byte(b)) + `"}`)
			checkChecked(t, raw)
		}
	}
	for n := 1; n <= 18; n++ {
		checkChecked(t, []byte(strings.Repeat(`{"x":`, n)+`0`+strings.Repeat(`}`, n)))
	}
}
func FuzzCheckedEquivalence(f *testing.F) {
	f.Add(fusedFixture())
	for _, s := range []string{`{"a":"\u0000"}`, `{"a":[1,-0,null]}`, `{"x":0,}`, `{"x":"\\\""}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) { checkChecked(t, raw) })
}
func BenchmarkCheckedPosting(b *testing.B) {
	raw := []byte(`{"kind":"attempt","payload":"` + strings.Repeat("YWJj", 2000) + `","seq":"42"}`)
	for _, fast := range []bool{false, true} {
		name := "previous"
		if fast {
			name = "checked"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var e error
				if fast {
					e = Validate(raw)
				} else {
					e = legacyCheckedValidate(raw)
				}
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
func TestCheckedSelectOriginalBytes(t *testing.T) {
	raw := []byte(` {"selected" : { "x": [1, "a\\b"] }, "other":null} `)
	got, e := SelectFields(raw, "selected")
	if e != nil || !bytes.Equal(got["selected"], []byte(`{ "x": [1, "a\\b"] }`)) {
		t.Fatal("selected bytes changed", got, e)
	}
}

// TestCheckedSchema は完全検査前の種別選択だけが持つ大小文字・null・重複の既存動作を保つ。
func TestCheckedSchema(t *testing.T) {
	for _, raw := range []string{`{}`, `{"schema":"form-post-v8"}`, `{"SCHEMA":"form-post-v8"}`, `{"ſchema":"form-post-v8"}`, `{"s_c_h_e_m_a":"form-post-v8"}`, `{"schema":"first","Schema":null}`, `{"schema":null}`, `{"schema":1,"schema":"last"}`, `{"schema":"first","schema":"last"}`, `{"schema":[]}`} {
		var want struct {
			Schema string `json:"schema"`
		}
		we := json.Unmarshal([]byte(raw), &want)
		got, ge := Schema([]byte(raw))
		if (we == nil) != (ge == nil) || we == nil && got != want.Schema {
			t.Fatalf("schema selection changed %s: %q/%q %v/%v", raw, want.Schema, got, we, ge)
		}
	}
}
func TestCheckedControlBits(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	var raw [64]byte
	for n := 0; n < 100000; n++ {
		for off := 0; off < len(raw); off += 8 {
			binary.LittleEndian.PutUint64(raw[off:], r.Uint64())
		}
		body := raw[:n%65]
		want := false
		for _, b := range body {
			want = want || b < 32
		}
		if hasControl(body) != want {
			t.Fatalf("control mismatch %x", body)
		}
	}
}
func BenchmarkCheckedSchema(b *testing.B) {
	raw := []byte(`{"schema":"form-post-v8","payload":"` + strings.Repeat("YWJj", 2000) + `"}`)
	for _, fast := range []bool{false, true} {
		name := "previous"
		if fast {
			name = "checked"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var e error
				if fast {
					_, e = Schema(raw)
				} else {
					var marker struct {
						Schema string `json:"schema"`
					}
					e = json.Unmarshal(raw, &marker)
				}
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}

// FuzzCheckedSchemaSelection は従来の種別選択と大小文字・型エラーの分類を照合する。
func FuzzCheckedSchemaSelection(f *testing.F) {
	f.Add("Schema", "form-post-v8", uint8(0))
	f.Add("ſchema", "unknown", uint8(1))
	f.Fuzz(func(t *testing.T, key, value string, mode uint8) {
		k, _ := json.Marshal(key)
		v, _ := json.Marshal(value)
		switch mode % 3 {
		case 1:
			v = []byte("1")
		case 2:
			v = []byte("null")
		}
		raw := append([]byte("{"), k...)
		raw = append(raw, ':')
		raw = append(raw, v...)
		raw = append(raw, `,"schema":null}`...)

		var want struct {
			Schema string `json:"schema"`
		}
		we := json.Unmarshal(raw, &want)
		got, ge := Schema(raw)
		if (we == nil) != (ge == nil) || we == nil && got != want.Schema {
			t.Fatalf("schema changed %s: %q/%q %v/%v", raw, want.Schema, got, we, ge)
		}
	})
}

// BenchmarkCheckedComposite は全体検証・型付き復号・再符号化を同じ値で比較する。
func BenchmarkCheckedComposite(b *testing.B) {
	raw := fusedFixture()
	for _, fast := range []bool{false, true} {
		name := "previous"
		if fast {
			name = "checked"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var e error
				var v fusedRecord
				if fast {
					e = Validate(raw)
					if e == nil {
						e = Decode(raw, &v)
					}
				} else {
					e = legacyCheckedValidate(raw)
					if e == nil {
						e = legacyCheckedDecode(raw, &v)
					}
				}
				if e != nil {
					b.Fatal(e)
				}
				if _, e = json.Marshal(v); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}

// TestSchemaFallbackPreservesDelegation は選択だけで未知形式の受理条件を狭めない。
func TestSchemaFallbackPreservesDelegation(t *testing.T) {
	cases := [][]byte{[]byte(`null`), []byte(`{"schema":"custom","other":"\u0000"}`), []byte(`{"schema":"custom","other":"\ud800"}`), []byte(`{"schema":"custom","other":` + strings.Repeat(`[`, 18) + `0` + strings.Repeat(`]`, 18) + `}`), []byte(`{"schema":"custom","other":"` + strings.Repeat("x", MaxBytes) + `"}`), append(append([]byte(`{"schema":"custom","other":"`), 255), []byte(`"}`)...)}
	for _, raw := range cases {
		var marker struct {
			Schema string `json:"schema"`
		}
		we := json.Unmarshal(raw, &marker)
		got, ge := Schema(raw)
		if (we == nil) != (ge == nil) || we == nil && marker.Schema != got {
			t.Fatalf("delegation changed: %v/%v", we, ge)
		}
		if len(raw) <= MaxBytes && Validate(raw) == nil {
			t.Fatal("selection fallback weakened full validation")
		}
	}
}
