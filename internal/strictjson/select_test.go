// 選択した値の元byteと、未選択部分を含む全体検査を標準復号へ照合する。
package strictjson

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzSelectFields(f *testing.F) {
	for _, raw := range []string{`{"a":1,"b":{"x":["a\\b",1,null]},"A":true}`, `{"\u0061":"\uD83D\uDE00","unused":[{},null]}`, `{"a":1,"\u0061":2}`, `{"unused":{"a":1,"a":2}}`, `{"a":1 ,"b":false }`, `{}`, `[]`, `null`, `{"unused":"\uD800"}`} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		names := []string{"a", "b", "A", "missing"}
		got, e := SelectFields(raw, names...)
		valid := Validate(raw) == nil
		if (e == nil) != valid {
			t.Fatalf("acceptance differs: %q", raw)
		}
		if !valid {
			if got != nil {
				t.Fatal("invalid JSON returned fields")
			}
			return
		}
		var want map[string]json.RawMessage
		if e = json.Unmarshal(raw, &want); e != nil {
			t.Fatal(e)
		}
		for _, name := range names {
			if !bytes.Equal(got[name], bytes.TrimSpace(want[name])) {
				t.Fatalf("field %q: %q != %q", name, got[name], want[name])
			}
		}
	})
}

func TestSelectFieldsBorrowedValues(t *testing.T) {
	raw := []byte(`{"a":"value","b":null}`)
	fields, e := SelectFields(raw, "a", "b", "missing")
	if e != nil || string(fields["a"]) != `"value"` || string(fields["b"]) != "null" || fields["missing"] != nil {
		t.Fatal(fields, e)
	}
	copy(raw[6:11], "other")
	if string(fields["a"]) != `"other"` {
		t.Fatal("field did not reference input")
	}
}
