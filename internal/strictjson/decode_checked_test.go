// 一走査復号を直前の二走査復号と照合し、失敗時の非公開性と保留した要素の所有権を検証する。
package strictjson

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// priorDecode は今回の変更前の構文検査と型付き復号を比較用に残す。
func priorDecode(body []byte, dst any) error {
	s, err := objectScanner(body)
	if err != nil {
		return err
	}
	if handled, err := decodeFresh(s, reflect.ValueOf(dst).Elem()); handled {
		return err
	}
	return unfusedDecode(body, dst)
}

func checkCheckedDecode(t testing.TB, body []byte) {
	t.Helper()
	var old, got fusedRecord
	oe, ge := priorDecode(body, &old), Decode(body, &got)
	if (oe == nil) != (ge == nil) || oe == nil && !reflect.DeepEqual(old, got) {
		t.Fatalf("decode differs: %q old=%v new=%v oldValue=%#v newValue=%#v", body, oe, ge, old, got)
	}
	if ge != nil && !reflect.DeepEqual(got, fusedRecord{}) {
		t.Fatalf("rejected input changed destination: %q", body)
	}
}

func TestCheckedDecodeSyntax(t *testing.T) {
	raw := fusedFixture()
	checkCheckedDecode(t, raw)
	for i := range raw {
		checkCheckedDecode(t, raw[:i])
		for _, c := range []byte{0, ' ', ',', ':', ']', '}', '"', '\\', '0', 0xff} {
			changed := bytes.Clone(raw)
			changed[i] = c
			checkCheckedDecode(t, changed)
		}
	}
	for _, extra := range []string{`0`, `,`, `[]`, `true`, `{"x":0}`} {
		checkCheckedDecode(t, append(bytes.Clone(raw), extra...))
	}
}

func FuzzCheckedDecodeEquivalence(f *testing.F) {
	f.Add(fusedFixture())
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, body []byte) { checkCheckedDecode(t, body) })
}

// FuzzCheckedDecodeStructured は構文が正しい入力を作り、文字列・数値・sliceの復号値も照合する。
func FuzzCheckedDecodeStructured(f *testing.F) {
	f.Add("日本語😀<&>\n", int64(-42), uint32(42), []byte{0, 1, 255})
	f.Fuzz(func(t *testing.T, name string, signed int64, count uint32, items []byte) {
		if len(items) > 257 {
			items = items[:257]
		}
		children := make([]shapeChild, len(items))
		for i, n := range items {
			children[i] = shapeChild{n%2 == 0, name}
		}
		v := fusedRecord{Name: name, Signed: signed, Count: count, Children: children,
			Fixed:   [2]uint64{uint64(count), uint64(count) * uint64(count)},
			Payload: json.RawMessage(`{"opaque":[null,true,1e3]}`), Map: map[string]*shapeChild{"nil": nil}}
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		// 保存型のbyte sliceは配列のみを受け付け、nullやbase64表現を許可しない。
		raw = bytes.Replace(raw, []byte(`"bytes":null`), []byte(`"bytes":[0,255]`), 1)
		checkCheckedDecode(t, raw)
	})
}

// TestCheckedDeferredSlice は再確保を要する要素数・入れ子・64件を超える独自復号を照合する。
func TestCheckedDeferredSlice(t *testing.T) {
	type row struct {
		Custom customShape `json:"custom"`
		Nested []fusedByte `json:"nested"`
	}
	type doc struct {
		Rows []row `json:"rows"`
	}
	for _, count := range []int{0, 1, 2, 15, 63, 64, 65, 257} {
		rows := make([]string, count)
		for i := range rows {
			rows[i] = `{"custom":{"v":1},"nested":[1,2,3,255]}`
		}
		raw := []byte(`{"rows":[` + strings.Join(rows, ",") + `]}`)
		var old, got doc
		if oe, ge := priorDecode(raw, &old), Decode(raw, &got); oe != nil || ge != nil || !reflect.DeepEqual(old, got) {
			t.Fatalf("slice count=%d: old=%v new=%v", count, oe, ge)
		}
	}
}

type countedDecode struct{}

var checkedDecodeCalls int

func (*countedDecode) UnmarshalJSON([]byte) error { checkedDecodeCalls++; return nil }

func TestCheckedDecodeDefersCallbacks(t *testing.T) {
	type doc struct {
		Custom countedDecode   `json:"custom"`
		Raw    json.RawMessage `json:"raw"`
	}
	for _, raw := range []string{
		`{"custom":{},"raw":0} trailing`,
		`{"custom":{},"raw":[0,]}`,
		`{"custom":{},"raw":{"a":1,"a":2}}`,
		`{"custom":{},"raw":"\ud800"}`,
	} {
		checkedDecodeCalls = 0
		var got doc
		if Decode([]byte(raw), &got) == nil || checkedDecodeCalls != 0 || !reflect.DeepEqual(got, doc{}) {
			t.Fatalf("invalid input invoked callback: %q calls=%d", raw, checkedDecodeCalls)
		}
	}
}

func BenchmarkCheckedDecode(b *testing.B) {
	for _, tc := range []struct {
		name   string
		decode func([]byte, any) error
	}{{"prior", priorDecode}, {"checked", Decode}} {
		b.Run(tc.name, func(b *testing.B) {
			body := fusedFixture()
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

func BenchmarkCheckedDefaultBool(b *testing.B) {
	for _, body := range []struct{ name, raw string }{
		{"present", `{"flag":false,"payload":"` + strings.Repeat("日本語", 128) + `"}`},
		{"omitted", `{"payload":"` + strings.Repeat("日本語", 128) + `"}`},
	} {
		b.Run(body.name, func(b *testing.B) {
			for _, tc := range []struct {
				name   string
				decode func([]byte, any, string, bool) error
			}{{"prior", priorDefaultBool}, {"checked", DecodeDefaultBool}} {
				b.Run(tc.name, func(b *testing.B) {
					raw := []byte(body.raw)
					b.ReportAllocs()
					for b.Loop() {
						var got defaultDocument
						if err := tc.decode(raw, &got, "flag", true); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func TestCheckedDefaultScope(t *testing.T) {
	type flagOnly struct {
		Flag bool `json:"flag"`
	}
	for _, value := range []bool{false, true} {
		var got flagOnly
		if err := DecodeDefaultBool([]byte(`{}`), &got, "flag", value); err != nil || got.Flag != value {
			t.Fatal("single default", err, got)
		}
	}
	type nested struct {
		Flag  bool     `json:"flag"`
		Child flagOnly `json:"child"`
	}
	for _, raw := range []string{`{"child":{}}`, `{"flag":true,"child":{}}`, `{"child":{"flag":null}}`} {
		var got nested
		if DecodeDefaultBool([]byte(raw), &got, "flag", true) == nil {
			t.Fatalf("nested default accepted: %s", raw)
		}
	}
	var got nested
	if err := DecodeDefaultBool([]byte(`{"child":{"flag":false}}`), &got, "flag", true); err != nil || !got.Flag || got.Child.Flag {
		t.Fatal("root default", err, got)
	}
}
