// 長さcodeの全範囲を、形式仕様の基準長と追加bit数で照合する。
package zstddecode

import "testing"

// TestLengthValueSpecification はRFC 8878 §3.1.1.3.2.1.1の表16・17を検証する。
func TestLengthValueSpecification(t *testing.T) {
	cases := []struct {
		name   string
		decode func(int) (int, int)
		base   []int
		bits   []int
	}{
		{
			name: "literal", decode: literalLengthValue,
			base: []int{
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256,
				512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
			},
			bits: []int{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8,
				9, 10, 11, 12, 13, 14, 15, 16,
			},
		},
		{
			name: "match", decode: matchLengthValue,
			base: []int{
				3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
				19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
				35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259,
				515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
			},
			bits: []int{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8,
				9, 10, 11, 12, 13, 14, 15, 16,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for code, want := range tc.base {
				base, bits := tc.decode(code)
				if base != want || bits != tc.bits[code] {
					t.Fatalf("code=%d: got (%d,%d), want (%d,%d)", code, base, bits, want, tc.bits[code])
				}
			}
		})
	}
}
