// 型検査と復号を一体化する経路を、従来の検査・標準復号との境界で照合する。
package strictjson

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type fusedRecord struct {
	Name     string                 `json:"name"`
	Count    uint32                 `json:"count"`
	Signed   int64                  `json:"signed"`
	Child    *shapeChild            `json:"child"`
	Children []shapeChild           `json:"children"`
	Fixed    [2]uint64              `json:"fixed"`
	Payload  json.RawMessage        `json:"payload"`
	Custom   customShape            `json:"custom"`
	Map      map[string]*shapeChild `json:"map"`
	Bytes    []byte                 `json:"bytes"`
}

// unfusedDecode は構文・厳密な型走査と標準復号を分離した現行版を保持する。
func unfusedDecode(body []byte, dst any) error {
	s, err := objectScanner(body)
	if err != nil {
		return err
	}
	if err := (&shapeScanner{keyScanner: s}).value(reflect.TypeOf(dst).Elem()); err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

func fusedFixture() []byte {
	return []byte(`{"name":"日本語😀","count":4294967295,"signed":-9223372036854775808,"child":{"active":true,"text":"text"},"children":[{"active":false,"text":""}],"fixed":[0,18446744073709551615],"payload":{"arbitrary":[null,true,1e3]},"custom":{"v":1},"map":{"a":{"active":true,"text":"a"}},"bytes":[1,255]}`)
}

func checkFusedDecode(t testing.TB, body []byte) {
	t.Helper()
	var old, got fusedRecord
	oe, ge := unfusedDecode(body, &old), Decode(body, &got)
	if (oe == nil) != (ge == nil) || oe == nil && !reflect.DeepEqual(old, got) {
		t.Fatalf("decode differs: %q old=%v new=%v", body, oe, ge)
	}
	if ge != nil && !reflect.DeepEqual(got, fusedRecord{}) {
		t.Fatalf("rejected input changed destination: %q", body)
	}
}

func TestFusedDecodeEquivalence(t *testing.T) {
	body := fusedFixture()
	checkFusedDecode(t, body)
	for _, pair := range [][2]string{
		{`"name":"日本語😀"`, `"name":"a\\\"\\b\/\ud83d\ude00"`},
		{`"count":4294967295`, `"count":4294967296`},
		{`"count":4294967295`, `"count":-0`},
		{`"count":4294967295`, `"count":1e0`},
		{`"signed":-9223372036854775808`, `"signed":-0`},
		{`"signed":-9223372036854775808`, `"signed":9223372036854775808`},
		{`"child":{"active":true,"text":"text"}`, `"child":null`},
		{`"children":[{"active":false,"text":""}]`, `"children":[]`},
		{`"children":[{"active":false,"text":""}]`, `"children":null`},
		{`"fixed":[0,18446744073709551615]`, `"fixed":[0]`},
		{`"custom":{"v":1}`, `"custom":{"v":1,"\u0076":2}`},
		{`"payload":{"arbitrary":[null,true,1e3]}`, `"payload":null`},
		{`"bytes":[1,255]`, `"bytes":"Af8="`},
		{`"map":{"a":{"active":true,"text":"a"}}`, `"map":{"a":null}`},
		{`"map":{"a":{"active":true,"text":"a"}}`, `"map":null`},
		{`"name":"日本語😀"`, `"name":"\ud800"`},
		{`"name":"日本語😀"`, `"name":"\u0000"`},
		{`"name":"日本語😀"`, `"Name":"a"`},
		{`"name":"日本語😀"`, `"name":"a","\u006eame":"b"`},
	} {
		checkFusedDecode(t, []byte(strings.Replace(string(body), pair[0], pair[1], 1)))
	}
}

func FuzzFusedDecodeEquivalence(f *testing.F) {
	f.Add(fusedFixture())
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, body []byte) { checkFusedDecode(t, body) })
}

func BenchmarkFusedDecode(b *testing.B) {
	body := fusedFixture()
	for _, tc := range []struct {
		name   string
		decode func([]byte, any) error
	}{{"unfused", unfusedDecode}, {"current", Decode}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var got fusedRecord
				if err := tc.decode(body, &got); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type fusedText string

func (v *fusedText) UnmarshalText(raw []byte) error {
	*v = fusedText("decoded:" + string(raw))
	return nil
}

// TestFusedFallback は既存値のmerge・特殊タグ・text型の標準復号を維持する。
func TestFusedFallback(t *testing.T) {
	type special struct {
		Number int         `json:"number,string"`
		Text   fusedText   `json:"text"`
		Raw    json.Number `json:"raw"`
	}
	raw := []byte(`{"number":"12","text":"v","raw":42}`)
	var old, got special
	if oe, ge := unfusedDecode(raw, &old), Decode(raw, &got); oe != nil || ge != nil || !reflect.DeepEqual(old, got) {
		t.Fatalf("special: %v %v %#v %#v", oe, ge, old, got)
	}
	type merged struct {
		Values map[string]int `json:"values"`
	}
	a, b := merged{map[string]int{"keep": 1}}, merged{map[string]int{"keep": 1}}
	raw = []byte(`{"values":{"new":2}}`)
	if oe, ge := unfusedDecode(raw, &a), Decode(raw, &b); oe != nil || ge != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("merge: %v %v", oe, ge)
	}
	type recursive struct {
		Name string     `json:"name"`
		Next *recursive `json:"next"`
	}
	var x, y recursive
	raw = []byte(`{"name":"a","next":{"name":"b","next":null}}`)
	if oe, ge := unfusedDecode(raw, &x), Decode(raw, &y); oe != nil || ge != nil || !reflect.DeepEqual(x, y) {
		t.Fatalf("recursive: %v %v", oe, ge)
	}
}

type fusedByte uint8

func (v *fusedByte) UnmarshalJSON(raw []byte) error {
	var n uint8
	if err := json.Unmarshal(raw, &n); err != nil {
		return err
	}
	*v = fusedByte(n ^ 7)
	return nil
}

// TestFusedCustomElements はslice・配列内の独自復号を、通常のbyte列と取り違えない。
func TestFusedCustomElements(t *testing.T) {
	type doc struct {
		Slice []fusedByte  `json:"slice"`
		Array [2]fusedByte `json:"array"`
	}
	for _, raw := range []string{`{"slice":[1,2,255],"array":[3,4]}`, `{"slice":[],"array":[0,0]}`, `{"slice":"AQI=","array":[0,0]}`} {
		var a, b doc
		oe, ge := unfusedDecode([]byte(raw), &a), Decode([]byte(raw), &b)
		if (oe == nil) != (ge == nil) || oe == nil && !reflect.DeepEqual(a, b) {
			t.Fatalf("custom byte: %v %v %#v %#v", oe, ge, a, b)
		}
	}
}
