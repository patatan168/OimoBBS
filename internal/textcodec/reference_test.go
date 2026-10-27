// 変更前の文字コード変換を回帰試験の独立した比較対象として保持する。
package textcodec

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

var referenceEncodeIndex = func() map[rune]int {
	m := make(map[rune]int, len(jis0208))
	for p, r := range jis0208 {
		if r == 0 || p >= 8272 && p <= 8835 {
			continue
		}
		if _, ok := m[r]; !ok {
			m[r] = p
		}
	}
	return m
}()

// Decode は不正なバイトを置換せずエラーにする。
func referenceDecode(b []byte) (string, error) {
	var s strings.Builder
	s.Grow(len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c < 0x80:
			start := i
			for i < len(b) && b[i] < 0x80 {
				i++
			}
			s.Write(b[start:i])
			i--
		case c <= 0x80:
			s.WriteRune(rune(c))
		case c >= 0xa1 && c <= 0xdf:
			s.WriteRune(rune(c) - 0xa1 + 0xff61)
		case c >= 0x81 && c <= 0x9f || c >= 0xe0 && c <= 0xfc:
			if i+1 == len(b) {
				return "", fmt.Errorf("incomplete Shift_JIS at %d", i)
			}
			i++
			d := b[i]
			if d < 0x40 || d > 0xfc || d == 0x7f {
				return "", fmt.Errorf("invalid Shift_JIS at %d", i)
			}
			off := 0x40
			if d >= 0x7f {
				off = 0x41
			}
			lead := 0x81
			if c >= 0xa0 {
				lead = 0xc1
			}
			p := (int(c)-lead)*188 + int(d) - off
			if p >= 8836 && p <= 10715 {
				s.WriteRune(rune(0xe000 + p - 8836))
				continue
			}
			if p >= len(jis0208) || jis0208[p] == 0 {
				return "", fmt.Errorf("unmapped Shift_JIS at %d", i)
			}
			s.WriteRune(jis0208[p])
		default:
			return "", fmt.Errorf("invalid Shift_JIS at %d", i)
		}
	}
	return s.String(), nil
}

// Encode は変換不能文字を、allowReferences時だけ十進参照として出力する。
func referenceEncode(s string, allowReferences bool) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	b := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r <= 0x80:
			b = append(b, byte(r))
		case r == 0xa5:
			b = append(b, 0x5c)
		case r == 0x203e:
			b = append(b, 0x7e)
		case r >= 0xff61 && r <= 0xff9f:
			b = append(b, byte(r-0xff61+0xa1))
		default:
			if r == 0x2212 {
				r = 0xff0d
			}
			p, ok := referenceEncodeIndex[r]
			if !ok {
				if !allowReferences {
					return nil, fmt.Errorf("unencodable character U+%04X", r)
				}
				b = append(b, "&#"...)
				b = strconv.AppendInt(b, int64(r), 10)
				b = append(b, ';')
				continue
			}
			lead := p / 188
			lo := 0x81
			if lead >= 0x1f {
				lo = 0xc1
			}
			trail := p % 188
			to := 0x40
			if trail >= 0x3f {
				to = 0x41
			}
			b = append(b, byte(lead+lo), byte(trail+to))
		}
	}
	return b, nil
}
