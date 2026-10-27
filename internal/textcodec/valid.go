// 文字列を生成せず、sjis-compat-v1の入力byteの妥当性だけを検査する。
package textcodec

import "encoding/binary"

// Valid はDecodeと同じbyte列を受理する。結果の文字列と一時配列は確保しない。
func Valid(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		i++
		if c <= 0x80 {
			for len(b)-i >= 8 && binary.LittleEndian.Uint64(b[i:])&0x8080808080808080 == 0 {
				i += 8
			}
			for i < len(b) && b[i] < 0x80 {
				i++
			}
			continue
		}
		if c >= 0xa1 && c <= 0xdf {
			continue
		}
		if !(c >= 0x81 && c <= 0x9f || c >= 0xe0 && c <= 0xfc) || i == len(b) {
			return false
		}
		d := b[i]
		i++
		if d < 0x40 || d > 0xfc || d == 0x7f {
			return false
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
			continue
		}
		if p >= len(jis0208) || jis0208[p] == 0 {
			return false
		}
	}
	return true
}
