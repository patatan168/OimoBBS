// literal長と参照長を専用計算へ分け、復号中の種別分岐を省く。
package zstddecode

// matchLengthValue は検証済み0〜52のcodeから参照の基準長と追加bit数を返す。
func matchLengthValue(code int) (int, int) {
	if code < 32 {
		return code + 3, 0
	}
	if code < 36 {
		return 35 + (code-32)*2, 1
	}
	if code < 38 {
		return 43 + (code-36)*4, 2
	}
	if code < 40 {
		return 51 + (code-38)*8, 3
	}
	if code < 42 {
		return 67 + (code-40)*16, 4
	}
	if code == 42 {
		return 99, 5
	}
	width := code - 36
	return (1 << uint(width)) + 3, width
}

// literalLengthValue は検証済み0〜35のcodeからliteralの基準長と追加bit数を返す。
func literalLengthValue(code int) (int, int) {
	if code < 16 {
		return code, 0
	}
	if code < 20 {
		return 16 + (code-16)*2, 1
	}
	if code < 22 {
		return 24 + (code-20)*4, 2
	}
	if code < 24 {
		return 32 + (code-22)*8, 3
	}
	if code == 24 {
		return 48, 4
	}
	width := code - 19
	return 1 << uint(width), width
}
