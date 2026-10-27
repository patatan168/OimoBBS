// 類似本文の旧計算との一致と、通常・長文・比較打切りの資源費用を検査する。
package bootstrap

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// referenceGuardSignature は変更前の全文rune変換と3文字ハッシュを比較基準にする。
func referenceGuardSignature(body string) guardSignature {
	text := strings.Join(strings.Fields(body), " ")
	chars := []rune(text)
	sig := guardSignature{exact: sha256.Sum256([]byte(text)), runes: len(chars)}
	unique := make(map[uint64]struct{})
	for i := 0; i+2 < len(chars); i++ {
		sum := sha256.Sum256([]byte(string(chars[i : i+3])))
		unique[binary.LittleEndian.Uint64(sum[:8])] = struct{}{}
		if len(unique) > guardSignatureLimit {
			sig.oversized = true
			return sig
		}
	}
	sig.grams = make([]uint64, 0, len(unique))
	for h := range unique {
		sig.grams = append(sig.grams, h)
	}
	slices.Sort(sig.grams)
	return sig
}

// referenceGuardSimilar は途中で止めず集合の交差を最後まで数える。
func referenceGuardSimilar(a, b guardSignature, minimum, percent int) bool {
	if a.exact == b.exact {
		return true
	}
	if a.runes < minimum || b.runes < minimum || a.oversized || b.oversized {
		return false
	}
	same := 0
	for _, value := range a.grams {
		if _, ok := slices.BinarySearch(b.grams, value); ok {
			same++
		}
	}
	union := len(a.grams) + len(b.grams) - same
	return union > 0 && same*100 >= union*percent
}

func FuzzGuardSignatureAndSimilarity(f *testing.F) {
	for _, pair := range [][2]string{{"", ""}, {"はい", "はい！"}, {"広告本文 abcdefghijklmnop", "広告本文 abcdefghijklmnoq"}, {"あ\u3000いう\nえ", "あ いう え"}, {"\xff\xfe日本語", "\xef\xbf\xbd日本語"}, {strings.Repeat("a", 32768), "aaa"}} {
		f.Add(pair[0], pair[1], uint8(90))
	}
	f.Fuzz(func(t *testing.T, left, right string, threshold uint8) {
		a, b := guardBodySignature(left), guardBodySignature(right)
		if !reflect.DeepEqual(a, referenceGuardSignature(left)) || !reflect.DeepEqual(b, referenceGuardSignature(right)) {
			t.Fatal("signature changed")
		}
		percent := 50 + int(threshold)%51
		if guardSimilar(a, b, 3, percent) != referenceGuardSimilar(a, b, 3, percent) {
			t.Fatal("similarity changed")
		}
	})
}

func TestGuardSimilarityThresholds(t *testing.T) {
	for n := 0; n <= 30; n++ {
		for m := 0; m <= 30; m++ {
			for common := 0; common <= min(n, m); common++ {
				a, b := guardSignature{exact: [32]byte{1}, runes: 100}, guardSignature{exact: [32]byte{2}, runes: 100}
				for i := range n {
					a.grams = append(a.grams, uint64(i))
				}
				for i := range m {
					value := i
					if i >= common {
						value += n
					}
					b.grams = append(b.grams, uint64(value))
				}
				for percent := 50; percent <= 100; percent++ {
					if guardSimilar(a, b, 3, percent) != referenceGuardSimilar(a, b, 3, percent) || guardSimilar(b, a, 3, percent) != referenceGuardSimilar(b, a, 3, percent) {
						t.Fatalf("n=%d m=%d common=%d percent=%d", n, m, common, percent)
					}
				}
			}
		}
	}
}

func BenchmarkGuardSignature(b *testing.B) {
	for name, body := range map[string]string{"normal": strings.Repeat("日本語本文 abcdefghijklmnopqrstuvwxyz 0123456789。", 8), "repeated-long": strings.Repeat("a", 32768), "unique-long": func() string {
		var s strings.Builder
		for i := range 5000 {
			s.WriteRune(rune(0x400 + i))
		}
		return s.String()
	}()} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = guardBodySignature(body)
			}
		})
	}
}

func BenchmarkGuardSimilarity(b *testing.B) {
	for _, size := range []int{128, 4096} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			a, c := guardSignature{exact: [32]byte{1}, runes: 5000}, guardSignature{exact: [32]byte{2}, runes: 5000}
			for i := range size {
				a.grams = append(a.grams, uint64(i*2))
				c.grams = append(c.grams, uint64(i*2+1))
			}
			b.ReportAllocs()
			for b.Loop() {
				_ = guardSimilar(a, c, 12, 90)
			}
		})
	}
}
