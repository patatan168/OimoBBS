// Unicode公式表からUTS #46の非移行変換とNFCを行い、比較用のASCIIラベルを構築する。
package urlhost

import (
	"sort"
	"strings"
)

type idnaRange struct {
	last   rune
	action uint8
	mapped string
}

// asciiDomain はブラウザーの非移行変換を適用する。ASCIIだけの一般的な宛先では表を走査しない。
func asciiDomain(host string) (string, bool) {
	if ascii(host) {
		return strings.ToLower(host), !forbidden(host)
	}
	var mapped strings.Builder
	for _, c := range host {
		i := sort.Search(len(idnaRanges), func(i int) bool { return idnaRanges[i].last >= c })
		if i == len(idnaRanges) {
			return "", false
		}
		row := idnaRanges[i]
		switch row.action {
		case 0:
			mapped.WriteRune(c)
		case 1:
			mapped.WriteString(row.mapped)
		case 2:
		default:
			return "", false
		}
	}
	normalized := normalizeNFC([]rune(mapped.String()))
	if forbidden(string(normalized)) {
		return "", false
	}
	labels := strings.Split(string(normalized), ".")
	for i, label := range labels {
		if ascii(label) {
			continue
		}
		encoded, ok := punycode([]rune(label))
		if !ok {
			return "", false
		}
		labels[i] = "xn--" + encoded
	}
	return strings.Join(labels, "."), true
}

func ascii(raw string) bool {
	for i := range len(raw) {
		if raw[i] >= 128 {
			return false
		}
	}
	return true
}

func forbidden(host string) bool {
	for _, c := range host {
		if c <= 32 || c == 127 || strings.ContainsRune("#%/:<>?@[\\]^|", c) {
			return true
		}
	}
	return false
}

// normalizeNFC は正準分解・結合順序・再結合を行う。長い結合文字列もO(n log n)で並べる。
func normalizeNFC(input []rune) []rune {
	decomposed := make([]rune, 0, len(input))
	for _, c := range input {
		decomposed = decompose(decomposed, c)
	}
	for start := 0; start < len(decomposed); {
		end := start + 1
		for end < len(decomposed) && canonicalClasses[decomposed[end]] != 0 {
			end++
		}
		marks := start
		if canonicalClasses[decomposed[start]] == 0 {
			marks++
		}
		sort.SliceStable(decomposed[marks:end], func(i, j int) bool {
			return canonicalClasses[decomposed[marks+i]] < canonicalClasses[decomposed[marks+j]]
		})
		start = end
	}
	out := decomposed[:0]
	starter, lastClass := -1, uint8(0)
	for _, c := range decomposed {
		class := canonicalClasses[c]
		if starter >= 0 && (lastClass < class || lastClass == 0) {
			if combined := compose(out[starter], c); combined != 0 {
				out[starter] = combined
				continue
			}
		}
		out = append(out, c)
		if class == 0 {
			starter = len(out) - 1
		}
		lastClass = class
	}
	return out
}

// decompose は正準分解表を再帰展開し、HangulだけはUnicodeの算術式で分解する。
func decompose(out []rune, c rune) []rune {
	if c >= 0xAC00 && c < 0xAC00+11172 {
		index := c - 0xAC00
		out = append(out, 0x1100+index/588, 0x1161+(index%588)/28)
		if index%28 != 0 {
			out = append(out, 0x11A7+index%28)
		}
		return out
	}
	if parts, ok := canonicalDecompositions[c]; ok {
		for _, part := range parts {
			out = decompose(out, part)
		}
		return out
	}
	return append(out, c)
}

// compose は正準結合の除外を反映した表と、Hangulの算術式で二文字を結合する。
func compose(a, b rune) rune {
	if a >= 0x1100 && a < 0x1113 && b >= 0x1161 && b < 0x1176 {
		return 0xAC00 + (a-0x1100)*588 + (b-0x1161)*28
	}
	if a >= 0xAC00 && a < 0xAC00+11172 && (a-0xAC00)%28 == 0 && b > 0x11A7 && b < 0x11C3 {
		return a + b - 0x11A7
	}
	return canonicalCompositions[uint64(a)<<21|uint64(b)]
}
