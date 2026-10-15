// Package compat は専ブラ向けフォームと固定文字コードの公開表現を生成する。
package compat

import (
	"errors"
	"mime"
	"net/url"
	"oimobbs/internal/textcodec"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrForm = errors.New("malformed form")
var ErrCharset = errors.New("unsupported media type or charset")
var numericRef = regexp.MustCompile(`&#(?:[0-9]+|[xX][0-9a-fA-F]+);`)

// ParseForm はqueryと混合せず最大64KiB・32組を厳密に復号する。
func ParseForm(body []byte, contentType string, web bool) (map[string]string, error) {
	if len(body) > 64<<10 {
		return nil, ErrForm
	}
	mt, params, e := mime.ParseMediaType(contentType)
	if e != nil || mt != "application/x-www-form-urlencoded" {
		return nil, ErrCharset
	}
	charset := strings.ToLower(params["charset"])
	if charset == "" {
		if web {
			charset = "utf-8"
		} else {
			charset = "shift_jis"
		}
	}
	if web && charset != "utf-8" {
		return nil, ErrCharset
	}
	if charset != "utf-8" && charset != "shift_jis" && charset != "windows-31j" && charset != "cp932" {
		return nil, ErrCharset
	}
	pairs := strings.Split(string(body), "&")
	if len(pairs) > 32 {
		return nil, ErrForm
	}
	out := map[string]string{}
	for _, pair := range pairs {
		k, v, _ := strings.Cut(pair, "=")
		k, e = url.QueryUnescape(k)
		if e != nil || k == "" {
			return nil, ErrForm
		}
		for _, r := range k {
			if r < 0x21 || r > 0x7e {
				return nil, ErrForm
			}
		}
		if _, ok := out[k]; ok {
			return nil, ErrForm
		}
		v, e = url.QueryUnescape(v)
		if e != nil {
			return nil, ErrForm
		}
		if charset == "utf-8" {
			if !utf8.ValidString(v) {
				return nil, ErrForm
			}
		} else {
			v, e = textcodec.Decode([]byte(v))
			if e != nil {
				return nil, ErrForm
			}
		}
		out[k] = v
	}
	return out, nil
}

// Normalize は数値参照を一段だけ戻し、改行と許可制御文字を検査する。
func Normalize(s string, body, references bool) (string, error) {
	if !utf8.ValidString(s) {
		return "", ErrForm
	}
	var invalid bool
	if references {
		s = numericRef.ReplaceAllStringFunc(s, func(ref string) string {
			n := ref[2 : len(ref)-1]
			base := 10
			if n[0] == 'x' || n[0] == 'X' {
				base = 16
				n = n[1:]
			}
			v, e := strconv.ParseUint(n, base, 32)
			if e != nil || v == 0 || v > utf8.MaxRune || v >= 0xd800 && v <= 0xdfff {
				invalid = true
				return ""
			}
			return string(rune(v))
		})
	}
	if invalid {
		return "", ErrForm
	}
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	for _, r := range s {
		if r == 127 || r < 32 && !(body && (r == '\n' || r == '\t')) {
			return "", ErrForm
		}
	}
	return s, nil
}
