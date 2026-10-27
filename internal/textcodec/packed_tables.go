// 固定文字表から出力byte列を事前計算し、変換中のmap検索・除算・UTF-8再符号化を省く。
package textcodec

import "unicode/utf8"

const leadMarker uint32 = 1

var encodePacked [1 << 16]uint16
var decodeSingles [256]uint32
var decodePairs [128 << 8]uint32

func init() {
	for p, r := range jis0208 {
		if r == 0 || p >= 8272 && p <= 8835 || encodePacked[r] != 0 {
			continue
		}
		lead := p/188 + 0x81
		if p/188 >= 0x1f {
			lead = p/188 + 0xc1
		}
		trail := p%188 + 0x40
		if p%188 >= 0x3f {
			trail++
		}
		encodePacked[r] = uint16(lead<<8 | trail)
	}
	encodePacked[0x80], encodePacked[0xa5], encodePacked[0x203e] = 0x80, 0x5c, 0x7e
	encodePacked[0x2212] = encodePacked[0xff0d]
	decodeSingles[0x80] = packedUTF8(0x80)
	for c := 0xa1; c <= 0xdf; c++ {
		decodeSingles[c] = packedUTF8(rune(c - 0xa1 + 0xff61))
		encodePacked[c-0xa1+0xff61] = uint16(c)
	}
	for c := 0x81; c <= 0xfc; c++ {
		if c > 0x9f && c < 0xe0 {
			continue
		}
		decodeSingles[c] = leadMarker
		for d := 0x40; d <= 0xfc; d++ {
			if d == 0x7f {
				continue
			}
			off, lead := 0x40, 0x81
			if d >= 0x7f {
				off++
			}
			if c >= 0xa0 {
				lead = 0xc1
			}
			p := (c-lead)*188 + d - off
			var r rune
			if p >= 8836 && p <= 10715 {
				r = rune(0xe000 + p - 8836)
			} else if p < len(jis0208) {
				r = jis0208[p]
			}
			if r != 0 {
				decodePairs[(c&127)<<8|d] = packedUTF8(r)
			}
		}
	}
}

// packedUTF8 はBMP内の固定文字を下位3byteと上位byteの長さに格納する。
func packedUTF8(r rune) uint32 {
	var buf [utf8.UTFMax]byte
	n := utf8.EncodeRune(buf[:], r)
	if n > 3 {
		panic("sjis-compat-v1 table contains a non-BMP rune")
	}
	return uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(n)<<24
}
