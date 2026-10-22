// 旧token実装との同値性と、投稿相当のJSON検証費用を測る。
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func tokenValidate(b []byte) error {
	if len(b) > MaxBytes || !utf8.Valid(b) {
		return errors.New("JSON size or UTF-8")
	}
	if err := unicodeEscapes(b); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return errors.New("object required")
	}
	if err = tokenContainer(d, '{', 1); err != nil {
		return err
	}
	if _, err = d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func tokenContainer(d *json.Decoder, kind json.Delim, depth int) error {
	if depth > 16 {
		return errors.New("JSON depth")
	}
	keys := map[string]bool{}
	for d.More() {
		if kind == '{' {
			k, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := k.(string)
			if !ok || keys[s] {
				return errors.New("duplicate or invalid key")
			}
			keys[s] = true
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if c, ok := t.(json.Delim); ok {
			if c != '{' && c != '[' {
				return errors.New("unexpected delimiter")
			}
			if err = tokenContainer(d, c, depth+1); err != nil {
				return err
			}
		}
	}
	end, err := d.Token()
	if err != nil {
		return err
	}
	want := json.Delim('}')
	if kind == '[' {
		want = ']'
	}
	if end != want {
		return errors.New("unclosed JSON")
	}
	return nil
}

func FuzzValidateMatchesToken(f *testing.F) {
	for _, seed := range []string{`{"a":[true,null,1,"あ"]}`, `{"a":1,"\u0061":2}`, `{"nested":{"a":1},"a":2}`, `{"a":"\\\"","b":[{},[]]}`, strings.Repeat(`{"x":`, 17) + `0` + strings.Repeat(`}`, 17), `{"a":"\ud83d\ude00"}`} {
		f.Add([]byte(seed))
	}
	var fields []string
	for i := range 33 {
		fields = append(fields, fmt.Sprintf(`"key%d":%d`, i, i))
	}
	f.Add([]byte("{" + strings.Join(fields, ",") + "}"))
	f.Add([]byte("{" + strings.Join(fields, ",") + `,"\u006bey0":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if (Validate(b) == nil) != (tokenValidate(b) == nil) {
			t.Fatalf("validation changed: %q", b)
		}
	})
}

// 全Unicode escapeと、表記の異なる同名キーを旧実装と照合する。
func TestValidateMatchesTokenEscapes(t *testing.T) {
	for n := 0; n <= 0xffff; n++ {
		body := []byte(fmt.Sprintf(`{"value":"\u%04x"}`, n))
		if (Validate(body) == nil) != (tokenValidate(body) == nil) {
			t.Fatalf("escape acceptance changed: %q", body)
		}
	}
	for _, body := range []string{
		`{"😀":1,"\ud83d\ude00":2}`, `{"a/b":1,"a\/b":2}`,
		`{"a\\b":1,"a\u005cb":2}`, `{"a\"b":1,"a\u0022b":2}`,
	} {
		if Validate([]byte(body)) == nil || tokenValidate([]byte(body)) == nil {
			t.Fatalf("duplicate escaped key accepted: %s", body)
		}
	}
}

// TestValidateKeySetBoundary は小さい集合からmapへ移る境界でも復号後の重複を拒否する。
func TestValidateKeySetBoundary(t *testing.T) {
	for _, count := range []int{0, 1, 15, 16, 17, 31, 32, 33, 256} {
		var fields []string
		for i := range count {
			fields = append(fields, fmt.Sprintf(`"key%d":%d`, i, i))
		}
		for _, extra := range []string{`"last":{}`, `"key0":null`, `"\u006bey0":[]`, `"key0":{"key0":1}`, `"last":{"a":1,"\u0061":2}`} {
			body := []byte("{" + strings.Join(append(fields[:len(fields):len(fields)], extra), ",") + "}")
			if (Validate(body) == nil) != (tokenValidate(body) == nil) {
				t.Fatalf("key count %d: %s", count, body)
			}
		}
	}
}

func BenchmarkValidatePosting(b *testing.B) {
	raw := []byte(`{"schema":1,"seq":"42","actor":{"kind":"system","reason":"evidence"},"mutations":[{"collection":"evidence_proposal","key":"abcdef","expected_revision":"0","value":{"payload":"` + strings.Repeat("YWJj", 2000) + `","signature":"AAAA","previous":"BBBB"},"expires":null}],"result":{"code":"saved","targets":[]}}`)
	for _, tc := range []struct {
		name string
		run  func([]byte) error
	}{{"token", tokenValidate}, {"scan", Validate}} {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for b.Loop() {
				if e := tc.run(raw); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
