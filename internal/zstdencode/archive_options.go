// 保存候補の実際の探索幅を照合し、圧縮byteが同じになる重複候補だけを省く。
package zstdencode

// uniqueArchiveOptions は検査済み候補を入力順に残す。呼出元の配列は変更しない。
// 適応prefixと固定prefixは全blockで同じ幅になる場合だけ同一とする。
func uniqueArchiveOptions(body []byte, options []ArchiveOptions) []ArchiveOptions {
	if len(options) < 2 {
		return options
	}
	var keep [4]int
	count := 0
	var masks archiveMaskChecks
	for i, option := range options {
		duplicate := false
		for _, index := range keep[:count] {
			if masks.equivalent(body, options[index], option) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			keep[count] = i
			count++
		}
	}
	if count == len(options) {
		return options
	}
	result := make([]ArchiveOptions, count)
	for i, index := range keep[:count] {
		result[i] = options[index]
	}
	return result
}

// adaptiveArchiveMaskMatches は全blockの適応prefixを確認し、最初の相違で終了する。
func adaptiveArchiveMaskMatches(body []byte, wanted uint64) bool {
	for begin := 0; begin < len(body); begin += blockLimit {
		_, mask, _ := literalPrices(body[begin:min(begin+blockLimit, len(body))])
		if mask != wanted {
			return false
		}
	}
	return true
}

// archiveMaskChecks は同じ本文に対する5/7byte幅の確認だけを一呼出し内で共有する。
type archiveMaskChecks struct{ checked, matches uint8 }

// equivalent は符号表の条件を先に照合し、適応prefixが関係する場合だけ本文を確認する。
func (m *archiveMaskChecks) equivalent(body []byte, prior, option ArchiveOptions) bool {
	if prior.AccuracyLog != option.AccuracyLog || prior.OptimizeEntropy != option.OptimizeEntropy {
		return false
	}
	if prior.HashBytes == option.HashBytes {
		return true
	}
	fixed := prior.HashBytes
	if fixed == 0 {
		fixed = option.HashBytes
	} else if option.HashBytes != 0 {
		return false
	}
	if fixed != 5 && fixed != 7 {
		return false
	}
	bit := uint8(1) << uint((fixed-5)/2)
	if m.checked&bit == 0 {
		m.checked |= bit
		if adaptiveArchiveMaskMatches(body, (uint64(1)<<uint(fixed*8))-1) {
			m.matches |= bit
		}
	}
	return m.matches&bit != 0
}
