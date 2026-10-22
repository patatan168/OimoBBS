// Package strictjson の永続形式に対する拒否条件を検査する。
package strictjson

import (
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	type record struct {
		Name  string `json:"name"`
		Count uint32 `json:"count"`
		Child *struct {
			OK bool `json:"ok"`
		} `json:"child"`
	}
	good := `{"name":"😀","count":1,"child":null}`
	var v record
	if err := Decode([]byte(good), &v); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`{"name":"a","name":"b","count":1,"child":null}`,
		`{"name":"a","\u006eame":"b","count":1,"child":null}`,
		`{"Name":"a","count":1,"child":null}`, `{"name":"a","count":1}`,
		`{"name":"\ud800","count":1,"child":null}`, `{"name":"\udc00","count":1,"child":null}`,
		`{"name":"\u0000","count":1,"child":null}`, `{"name":"a","count":1e0,"child":null}`,
		`{"name":"a","count":-0,"child":null}`, `{"name":null,"count":1,"child":null}`,
		`{"name":"a","count":1,"child":{"OK":true}}`, good + `{}`, string([]byte{'{', '"', 0xff, '"', ':', '1', '}'}),
	} {
		if err := Decode([]byte(s), &v); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}
func FuzzValidate(f *testing.F) {
	f.Add([]byte(`{"a":[true,null,1,"あ"]}`))
	f.Fuzz(func(t *testing.T, b []byte) { _ = Validate(b) })
}

func TestDepthAndRequiredArray(t *testing.T) {
	for depth := 1; depth <= 17; depth++ {
		s := strings.Repeat(`{"x":`, depth) + `0` + strings.Repeat(`}`, depth)
		e := Validate([]byte(s))
		if (e == nil) != (depth <= 16) {
			t.Fatalf("depth %d: %v", depth, e)
		}
	}
	var v struct {
		Items []string `json:"items"`
	}
	if e := Decode([]byte(`{"items":null}`), &v); e == nil {
		t.Fatal("null array accepted")
	}
	if e := Decode([]byte(`{"items":[]}`), &v); e != nil {
		t.Fatal(e)
	}
}
