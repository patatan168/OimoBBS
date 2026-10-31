// 文字列の検査と復号を標準JSONおよび既存のUnicode制約へ照合する。
package strictjson

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzCheckedEscapedString(f *testing.F) {
	for _, raw := range []string{`"plain"`, `"a\"b\\c\/d\b\f\n\r\t"`, `"\u003e\u003c\u0026"`, `"\ud83d\ude00"`, `"\ud800"`, `"\u0000"`, `"quote\""`, `"日本語\n本文"`} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 || !utf8.Valid(raw) {
			return
		}
		body := bytes.TrimSpace(raw)
		s := checkedScanner{keyScanner: keyScanner{body: body}, strict: true}
		got, err := s.checkedString(true)
		var want string
		oldErr := json.Unmarshal(raw, &want)
		valid := len(body) > 0 && body[0] == '"' && oldErr == nil && unicodeEscapes(raw) == nil && !strings.ContainsRune(want, 0)
		accepted := err == nil && s.pos == len(body)
		if accepted != valid || accepted && !bytes.Equal(got, []byte(want)) {
			t.Fatalf("%q: %q %v, want %q %v", raw, got, err, want, oldErr)
		}
	})
}

func BenchmarkCheckedEscapedString(b *testing.B) {
	for name, raw := range map[string]string{
		"post":  `"` + strings.Repeat(`本文\u003e\u003e123\nhttps://example.invalid/abc `, 8) + `"`,
		"plain": `"` + strings.Repeat("abcdef123456", 30) + `"`,
		"quote": `"` + strings.Repeat(`a\"b\\c\/d`, 30) + `"`,
	} {
		b.Run(name, func(b *testing.B) {
			body := []byte(raw)
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				s := checkedScanner{keyScanner: keyScanner{body: body}, strict: true}
				if _, err := s.checkedString(true); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
