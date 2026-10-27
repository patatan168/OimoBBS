// RFC 3492のPunycode符号化を、外部依存なしでURLのホスト比較へ使う。
package urlhost

// punycode はUnicodeラベルを符号化する。二次の走査は256文字までに制限する。
func punycode(input []rune) (string, bool) {
	if len(input) > 256 {
		return "", false
	}
	out := make([]byte, 0, len(input)+16)
	for _, c := range input {
		if c < 128 {
			out = append(out, byte(c))
		}
	}
	basic := len(out)
	if basic != 0 {
		out = append(out, '-')
	}
	n, delta, bias := int64(128), int64(0), int64(72)
	for done := basic; done < len(input); n++ {
		next := int64(0x110000)
		for _, c := range input {
			if int64(c) >= n && int64(c) < next {
				next = int64(c)
			}
		}
		delta += (next - n) * int64(done+1)
		n = next
		for _, c := range input {
			if int64(c) < n {
				delta++
			}
			if int64(c) != n {
				continue
			}
			q := delta
			for k := int64(36); ; k += 36 {
				threshold := max(int64(1), min(int64(26), k-bias))
				if q < threshold {
					break
				}
				out = append(out, punyDigit(threshold+(q-threshold)%(36-threshold)))
				q = (q - threshold) / (36 - threshold)
			}
			out = append(out, punyDigit(q))
			bias = adaptBias(delta, int64(done+1), done == basic)
			delta = 0
			done++
		}
		delta++
	}
	return string(out), true
}

func punyDigit(n int64) byte {
	if n < 26 {
		return byte('a' + n)
	}
	return byte('0' + n - 26)
}

// adaptBias はRFC 3492の差分の偏りを調整する。最初の非ASCII文字だけ減衰率を変える。
func adaptBias(delta, points int64, first bool) int64 {
	if first {
		delta /= 700
	} else {
		delta /= 2
	}
	delta += delta / points
	k := int64(0)
	for delta > 455 {
		delta /= 35
		k += 36
	}
	return k + 36*delta/(delta+38)
}
