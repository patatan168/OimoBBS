// 保存型の走査を旧復号方式と比較し、必須・null・独自復号・配列の境界を検査する。
package strictjson

import (
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type shapeChild struct {
	Active bool   `json:"active"`
	Text   string `json:"text"`
}

type shapeDocument struct {
	Name     string                 `json:"name"`
	Count    uint64                 `json:"count"`
	Signed   int64                  `json:"signed"`
	Child    *shapeChild            `json:"child"`
	Children []shapeChild           `json:"children"`
	Fixed    [2]uint64              `json:"fixed"`
	Payload  json.RawMessage        `json:"payload"`
	Map      map[string]*shapeChild `json:"map"`
}

type customShape struct{ value json.RawMessage }

// UnmarshalJSON は保存型が独自の制約を持つ場合の、型走査による検査省略を検証する。
func (v *customShape) UnmarshalJSON(body []byte) error {
	v.value = append(v.value[:0], body...)
	return nil
}

// shapeFixture は投稿capture相当の長い値を持つ型付き本文を生成する。
func shapeFixture(t testing.TB) []byte {
	t.Helper()
	child := shapeChild{true, strings.Repeat("日本語の本文と記録。", 300)}
	value := shapeDocument{Name: "記録", Count: 42, Signed: -42, Child: &child,
		Children: []shapeChild{child, child}, Fixed: [2]uint64{1, 2},
		Payload: json.RawMessage(`{"opaque":[null,{"v":"\\\""}]}`),
		Map:     map[string]*shapeChild{"nullable": nil, "value": &child}}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// referenceDecode は変更前の型検査と最後の標準復号を組み合わせる。
func referenceDecode(body []byte, dst any) error {
	if err := Validate(body); err != nil {
		return err
	}
	if err := referenceShape(body, reflect.TypeOf(dst).Elem()); err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

func FuzzDecodeShapeEquivalence(f *testing.F) {
	f.Add(shapeFixture(f))
	for _, body := range []string{
		`{}`, `{"items":[]}`, `{"items":null}`, `{"items":[1,2]}`, `{"items":"AQI="}`,
		`{"items":[-0,1e0]}`, `{"items":[1,2,3]}`, `{"items":{"active":true,"text":"あ"}}`,
		`{"items":{"active":true,"text":null}}`, `{"items":{"active":true}}`,
		`{"items":{},"Items":null}`, `{"items":null,"\u0069tems":null}`,
		`{"items":{"raw":null}}`, `{"items":{"raw":{"a":"\ud800"}}}`,
		`{"items":{"unknown":[{},null]}}`, `{"items":true}`, `{"items":"\\\"end"}`,
	} {
		f.Add([]byte(body))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		factories := []func() any{
			func() any { return new(shapeDocument) },
			func() any {
				return &struct {
					Items []uint8 `json:"items"`
				}{}
			},
			func() any {
				return &struct {
					Items [2]int64 `json:"items"`
				}{}
			},
			func() any {
				return &struct {
					Items *shapeChild `json:"items"`
				}{}
			},
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
					Items map[string]*shapeChild `json:"items"`
				}{}
			},
			func() any { return new(struct{}) },
		}
		for _, factory := range factories {
			a, b := factory(), factory()
			oldErr, newErr := referenceDecode(body, a), Decode(body, b)
			if (oldErr == nil) != (newErr == nil) || oldErr == nil && !reflect.DeepEqual(a, b) {
				t.Fatalf("decode changed for %T: old=%v new=%v", a, oldErr, newErr)
			}
		}
	})
}

func TestShapeConcurrentMetadata(t *testing.T) {
	body := shapeFixture(t)
	var expected shapeDocument
	if err := referenceDecode(body, &expected); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			var got shapeDocument
			if err := Decode(body, &got); err != nil || !reflect.DeepEqual(got, expected) {
				t.Error("concurrent decode", err)
			}
		})
	}
	workers.Wait()
}

func BenchmarkStrictDecodeShape(b *testing.B) {
	body := shapeFixture(b)
	for _, tc := range []struct {
		name   string
		decode func([]byte, any) error
	}{{"reference", referenceDecode}, {"scan", Decode}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				var got shapeDocument
				if err := tc.decode(body, &got); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
