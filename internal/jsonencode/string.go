// JSON文字列の通常経路を割当なしで引用し、既存のHTML・Unicode表記を保つ。
package jsonencode

import (
	"encoding/json"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

var plainJSONByte = func() (safe [256]bool) {
	for c := 0x20; c < 0x80; c++ {
		safe[c] = true
	}
	for _, c := range []byte{'"', '\\', '<', '>', '&'} {
		safe[c] = false
	}
	return safe
}()

// AppendString はdstへ標準json.Marshalと同じ文字列表記を追記する。
// 不正UTF-8だけは標準実装の置換規則へ委ね、部分出力を返さない。
func AppendString(dst []byte, s string) []byte {
	base := len(dst)
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		b := s[i]
		if plainJSONByte[b] {
			i++
			continue
		}
		if b < utf8.RuneSelf {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\')
			switch b {
			case '"', '\\':
				dst = append(dst, b)
			case '\n':
				dst = append(dst, 'n')
			case '\r':
				dst = append(dst, 'r')
			case '\t':
				dst = append(dst, 't')
			case '\b':
				dst = append(dst, 'b')
			case '\f':
				dst = append(dst, 'f')
			default:
				dst = append(dst, 'u', '0', '0', hexDigits[b>>4], hexDigits[b&15])
			}
			i++
			start = i
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			raw, _ := json.Marshal(s)
			return append(dst[:base], raw...)
		}
		if r == 0x2028 || r == 0x2029 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', hexDigits[byte(r)&15])
			start = i + n
		}
		i += n
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}
