// Package textcodec はsjis-compat-v1を標準ライブラリと固定表だけで変換する。
package textcodec

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Decode は不正なbyteを置換せず、入力全体を復号できたときだけ専有文字列を返す。
// 大きな非ASCII入力はCPUと共有枠の空きに応じて最大4workerで処理する。
func Decode(b []byte) (string, error) {
	prefix := asciiPrefixBytes(b)
	if prefix != len(b) && len(b) >= parallelMinimum {
		activeConversions.Add(1)
		defer activeConversions.Add(-1)
		if helpers := reserveCodecHelpers(len(b)); helpers != 0 {
			return decodeParallel(b, prefix, helpers)
		}
	}
	return decodeString(b, 0, prefix)
}

// decodeString は検査済みASCII prefixを一括copyし、固定表の出力byteを直接書く。
// baseは分割前の入力位置で、エラー位置を元の入力全体に合わせる。
func decodeString(b []byte, base, prefix int) (string, error) {
	if prefix == len(b) {
		return string(b), nil
	}
	var out strings.Builder
	capacity := len(b)
	if len(b) >= 128 {
		capacity += (len(b) - prefix) / 2
		// 半角カナで始まる区間は最大3倍へ展開するため、再確保を抑える。
		if b[prefix] >= 0xa1 && b[prefix] <= 0xdf {
			capacity = len(b) + 2*(len(b)-prefix)
		}
	}
	out.Grow(capacity)
	out.Write(b[:prefix])
	var glyph [3]byte
	for i := prefix; i < len(b); {
		if b[i] < 0x80 {
			n := asciiPrefixBytes(b[i:])
			out.Write(b[i : i+n])
			i += n
			continue
		}
		entry := decodeSingles[b[i]]
		if entry == 0 {
			return "", fmt.Errorf("invalid Shift_JIS at %d", base+i)
		}
		if entry == leadMarker {
			if i+1 == len(b) {
				return "", fmt.Errorf("incomplete Shift_JIS at %d", base+i)
			}
			entry = decodePairs[uint16(b[i]&127)<<8|uint16(b[i+1])]
			i++
			if entry == 0 {
				kind := "unmapped"
				if b[i] < 0x40 || b[i] > 0xfc || b[i] == 0x7f {
					kind = "invalid"
				}
				return "", fmt.Errorf("%s Shift_JIS at %d", kind, base+i)
			}
		}
		glyph[0], glyph[1], glyph[2] = byte(entry), byte(entry>>8), byte(entry>>16)
		out.Write(glyph[:entry>>24])
		i++
	}
	return out.String(), nil
}

// Encode は変換不能文字を、allowReferences時だけ十進参照として出力する。
// 大きな非ASCII入力はUTF-8検証も分担する。不正UTF-8は変換不能文字より先に拒否する。
func Encode(s string, allowReferences bool) ([]byte, error) {
	prefix := asciiPrefixString(s)
	if prefix == len(s) {
		return []byte(s), nil
	}
	if len(s) >= parallelMinimum {
		activeConversions.Add(1)
		defer activeConversions.Add(-1)
		if helpers := reserveCodecHelpers(len(s)); helpers != 0 {
			return encodeParallel(s, allowReferences, helpers)
		}
	}
	if !utf8.ValidString(s[prefix:]) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	out := make([]byte, 0, len(s))
	out = append(out, s[:prefix]...)
	return appendEncoded(out, s[prefix:], allowReferences)
}

// appendEncoded は有効なUTF-8を追記し、ASCIIの連続部分と事前計算したSJIS byteを使う。
func appendEncoded(out []byte, s string, allowReferences bool) ([]byte, error) {
	for len(s) > 0 {
		if s[0] < 0x80 {
			n := asciiPrefixString(s)
			out = append(out, s[:n]...)
			s = s[n:]
			continue
		}
		// 検証済みUTF-8の半角カナは3byteから1byteへ直接変換する。
		if len(s) >= 3 && s[0] == 0xef {
			if s[1] == 0xbd && s[2] >= 0xa1 {
				out = append(out, s[2])
				s = s[3:]
				continue
			}
			if s[1] == 0xbe && s[2] <= 0x9f {
				out = append(out, s[2]+0x40)
				s = s[3:]
				continue
			}
		}
		r, width := utf8.DecodeRuneInString(s)
		s = s[width:]
		var encoded uint16
		if r < 1<<16 {
			encoded = encodePacked[uint16(r)]
		}
		if encoded != 0 {
			if encoded < 256 {
				out = append(out, byte(encoded))
			} else {
				out = append(out, byte(encoded>>8), byte(encoded))
			}
			continue
		}
		if !allowReferences {
			return nil, fmt.Errorf("unencodable character U+%04X", r)
		}
		out = append(out, '&', '#')
		out = strconv.AppendInt(out, int64(r), 10)
		out = append(out, ';')
	}
	return out, nil
}
