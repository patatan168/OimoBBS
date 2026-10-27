// 生成復号器の共通readerについて、構文・Unicode・整数・深さと所有権を検査する。
package strictjson

import (
	"bytes"
	"testing"
)

func TestTypedReaderValues(t *testing.T) {
	r := NewTypedReader([]byte(`{"text":"あ\n\ud83d\ude00","array":[0,255],"null":null,"u":"18446744073709551615","i":"-9223372036854775808","raw":{"x":null}}`), MaxBytes)
	o := r.Object()
	for o.Next() {
		switch string(o.Key) {
		case "text":
			if got := r.String(); got != "あ\n😀" {
				t.Fatal(got)
			}
		case "array":
			a := r.Array()
			var values []uint64
			for a.Next() {
				values = append(values, r.Uint(8))
			}
			if len(values) != 2 || values[1] != 255 {
				t.Fatal(values)
			}
		case "null":
			if !r.Null() {
				t.Fatal("null")
			}
		case "u":
			if r.UintString() != ^uint64(0) {
				t.Fatal("uint64")
			}
		case "i":
			if r.IntString() != -1<<63 {
				t.Fatal("int64")
			}
		case "raw":
			if !bytes.Equal(r.Raw(), []byte(`{"x":null}`)) {
				t.Fatal("raw")
			}
		default:
			t.Fatal(string(o.Key))
		}
	}
	if err := r.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestTypedReaderRejects(t *testing.T) {
	for _, raw := range []string{`{"x":256}`, `{"x":-0}`, `{"x":1.0}`, `{"x":1e0}`, `{"x":null}`, `{"x":0,}`, `{"x":0} trailing`, `{"x":0`, `{"x":0 "other":0}`} {
		r := NewTypedReader([]byte(raw), MaxBytes)
		o := r.Object()
		for o.Next() {
			r.Uint(8)
		}
		if r.Finish() == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, value := range []string{`null`, `"\u0000"`, `"\ud800"`, `"\udc00"`, `"\ud800x"`, "\"\xff\"", `"unterminated`} {
		r := NewTypedReader([]byte(`{"x":`+value+`}`), MaxBytes)
		o := r.Object()
		for o.Next() {
			_ = r.String()
		}
		if r.Finish() == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	for _, value := range []string{`"+1"`, `"01"`, `"-0"`, `"1e0"`, `"18446744073709551616"`, `1`, `null`} {
		r := NewTypedReader([]byte(`{"x":`+value+`}`), MaxBytes)
		o := r.Object()
		for o.Next() {
			r.UintString()
		}
		if r.Finish() == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}

func TestTypedReaderRawBoundaries(t *testing.T) {
	for _, raw := range []string{`{"x":{"k":1,"k":2}}`, `{"x":"\ud800"}`, `{"x":` + string(bytes.Repeat([]byte{'['}, 16)) + `0` + string(bytes.Repeat([]byte{']'}, 16)) + `}`} {
		r := NewTypedReader([]byte(raw), MaxBytes)
		o := r.Object()
		for o.Next() {
			r.Raw()
		}
		if r.Finish() == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, limit := range []int{-1, 0, 1, 8<<20 + 1} {
		r := NewTypedReader([]byte(`{}`), limit)
		o := r.Object()
		for o.Next() {
			r.Raw()
		}
		if r.Finish() == nil {
			t.Fatal(limit)
		}
	}
	body := []byte(`{"x":[1]}`)
	r := NewTypedReader(body, MaxBytes)
	o := r.Object()
	var raw []byte
	for o.Next() {
		raw = r.Raw()
	}
	if r.Finish() != nil {
		t.Fatal("raw")
	}
	body[6] = '9'
	if string(raw) != `[1]` {
		t.Fatal("borrowed raw")
	}
}
