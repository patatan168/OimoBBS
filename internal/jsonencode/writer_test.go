// 文字列とサイズ上界を標準JSONへ差分照合し、escapeとoverflowの境界を検査する。
package jsonencode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func checkString(t testing.TB, s string) {
	t.Helper()
	want, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	got := AppendString([]byte("prefix"), s)
	if !bytes.Equal(got[6:], want) || string(got[:6]) != "prefix" {
		t.Fatalf("quote mismatch %q: %s / %s", s, want, got)
	}
	for _, limit := range []int{0, 1, 128, 128 << 10} {
		w := Writer{BoundOnly: true, Limit: limit}
		w.String(s)
		if len(want) > limit && w.Size <= limit || w.Size <= limit && w.Size < len(want) {
			t.Fatalf("unsafe bound %d/%d", w.Size, len(want))
		}
	}
}
func TestStringUnicodeAndControls(t *testing.T) {
	for r := rune(0); r <= utf8.MaxRune; r++ {
		checkString(t, string(r))
	}
	for _, s := range []string{strings.Repeat("<&>\\\"\n", 1000), string([]byte{0xff, 0xfe, 0xed, 0xa0, 0x80}), "日本語\u2028\u2029😀"} {
		checkString(t, s)
	}
}
func FuzzString(f *testing.F) {
	f.Add("日本語<&>\n\u2028")
	f.Add(string([]byte{255}))
	f.Fuzz(func(t *testing.T, s string) { checkString(t, s) })
}
func TestRawSemantics(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, []byte(` { "x" : "<>&" } `), []byte(`{"x":`), []byte(`{"x":1,"x":2}`)} {
		want, we := json.Marshal(raw)
		w := Writer{}
		w.Raw(raw)
		if (we == nil) != (w.Err == nil) || we == nil && !bytes.Equal(w.Bytes, want) {
			t.Fatalf("raw mismatch %q %v %v", raw, we, w.Err)
		}
	}
}
func BenchmarkString(b *testing.B) {
	s := strings.Repeat("投稿<&>日本語\nASCII", 30)
	for _, fast := range []bool{false, true} {
		name := "standard"
		if fast {
			name = "direct"
		}
		b.Run(name, func(b *testing.B) {
			buf := make([]byte, 0, len(s)*2)
			b.ReportAllocs()
			for b.Loop() {
				if fast {
					buf = AppendString(buf[:0], s)
				} else {
					var e error
					buf, e = json.Marshal(s)
					if e != nil {
						b.Fatal(e)
					}
				}
			}
		})
	}
}
