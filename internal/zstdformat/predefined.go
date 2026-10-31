// Package zstdformat は符号器と復号器が共有する形式上の定数を定義する。
package zstdformat

// Predefined はRFC 8878 §3.1.1.3.2.2の正規化頻度を値で返す。
// 列はliteral長・offset・参照長の順。-1は表の末尾へ配置する低頻度記号。
// 未対応の列ではlengthを0にする。返却配列の変更は他の呼出しへ影響しない。
func Predefined(column int) (counts [53]int, log uint, length int) {
	switch column {
	case 0:
		log, length = 6, 36
		for i := range length {
			switch {
			case i == 0:
				counts[i] = 4
			case i == 1 || i == 25:
				counts[i] = 3
			case i >= 32:
				counts[i] = -1
			case i >= 13 && i <= 15 || i >= 27:
				counts[i] = 1
			default:
				counts[i] = 2
			}
		}
	case 1:
		log, length = 5, 29
		for i := range length {
			switch {
			case i >= 24:
				counts[i] = -1
			case i >= 6 && i <= 8:
				counts[i] = 2
			default:
				counts[i] = 1
			}
		}
	case 2:
		log, length = 6, 53
		for i := range length {
			switch {
			case i >= 46:
				counts[i] = -1
			case i == 1:
				counts[i] = 4
			case i == 2:
				counts[i] = 3
			case i >= 3 && i <= 8:
				counts[i] = 2
			default:
				counts[i] = 1
			}
		}
	}
	return
}
