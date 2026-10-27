// 型付き走査でも、未知の本文・独自復号器・大きい保存型の厳密検査を維持する。
package strictjson

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeFusedFieldBoundaries(t *testing.T) {
	for _, count := range []int{0, 1, 32, 64, 65, 255, 256, 257, 300} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fields := make([]reflect.StructField, count)
			values := make(map[string]uint64, count)
			for i := range fields {
				name := fmt.Sprintf("k%d", i)
				fields[i] = reflect.StructField{Name: fmt.Sprintf("Field%d", i), Type: reflect.TypeFor[uint64](), Tag: reflect.StructTag(fmt.Sprintf(`json:"%s"`, name))}
				values[name] = uint64(i)
			}
			typ := reflect.StructOf(fields)
			raw, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			check := func(body []byte, valid bool) {
				t.Helper()
				old, got := reflect.New(typ).Interface(), reflect.New(typ).Interface()
				oe, ge := referenceDecode(body, old), Decode(body, got)
				if (oe == nil) != valid || (ge == nil) != valid || valid && !reflect.DeepEqual(old, got) {
					t.Fatalf("changed acceptance: old=%v new=%v", oe, ge)
				}
			}
			check(raw, true)
			if count == 0 {
				check([]byte(`{"extra":0}`), false)
				return
			}
			check([]byte(strings.Replace(string(raw), `"k0"`, `"\u006b0"`, 1)), true)
			for _, index := range []int{0, count - 1} {
				extra := fmt.Sprintf(`,"k%d":0}`, index)
				check(append(append([]byte{}, raw[:len(raw)-1]...), extra...), false)
			}
			check(append(append([]byte{}, raw[:len(raw)-1]...), `,"\u006b0":0}`...), false)
			delete(values, fmt.Sprintf("k%d", count-1))
			missing, _ := json.Marshal(values)
			check(missing, false)
		})
	}
}

func TestDecodeFusedOpaqueDepthAndUnicode(t *testing.T) {
	factories := []func() any{
		func() any {
			return &struct {
				Items json.RawMessage `json:"items"`
			}{}
		},
		func() any {
			return &struct {
				Items customShape `json:"items"`
			}{}
		},
		func() any {
			return &struct {
				Items map[string]any `json:"items"`
			}{}
		},
		func() any {
			return &struct {
				Items []json.RawMessage `json:"items"`
			}{}
		},
	}
	var bodies []string
	for _, value := range []string{`{"a":1,"\u0061":2}`, `{"a":"\ud800"}`, `{"a":"\udc00"}`, `{"a":"\u0000"}`, `{"a":"\ud83d\ude00"}`} {
		bodies = append(bodies, `{"items":`+value+`}`, `{"items":[`+value+`]}`)
	}
	for depth := 13; depth <= 17; depth++ {
		bodies = append(bodies, `{"items":`+strings.Repeat(`{"v":`, depth)+`0`+strings.Repeat(`}`, depth)+`}`)
		bodies = append(bodies, `{"items":`+strings.Repeat(`[`, depth)+`0`+strings.Repeat(`]`, depth)+`}`)
	}
	for _, body := range bodies {
		for _, factory := range factories {
			old, got := factory(), factory()
			oe, ge := referenceDecode([]byte(body), old), Decode([]byte(body), got)
			if (oe == nil) != (ge == nil) || oe == nil && !reflect.DeepEqual(old, got) {
				t.Fatalf("changed %T: %s old=%v new=%v", got, body, oe, ge)
			}
		}
	}
}
