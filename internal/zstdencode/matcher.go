// 頻度に応じて探索幅を選び、参照の費用と有界な候補表で圧縮率・速度を調整する。
package zstdencode

import (
	"encoding/binary"
	"math/bits"
)

// longHash は選んだprefix幅の一致候補をindexとfingerprintで絞る。
func longHash(value, mask uint64) uint32 {
	return uint32((value & mask) * 0x9e3779b185ebca87 >> 32)
}

// matchLength は8byteずつ比較し、末尾だけbyte単位で確認する。
func matchLength(body []byte, a, b, end, known int) int {
	n := known
	for b+n+8 <= end {
		different := binary.LittleEndian.Uint64(body[a+n:a+n+8]) ^ binary.LittleEndian.Uint64(body[b+n:b+n+8])
		if different != 0 {
			return n + bits.TrailingZeros64(different)/8
		}
		n += 8
	}
	for b+n < end && body[a+n] == body[b+n] {
		n++
	}
	return n
}

// bitPrice は対数を固定小数点で求め、CPUの浮動小数点差で出力が変わることを避ける。
func bitPrice(total, count int) int {
	ratio := (uint64(total) << 31) / uint64(count)
	whole := bits.Len64(ratio) - 32
	value := ratio >> uint(whole)
	fraction := 0
	for range 8 {
		value = value * value >> 31
		fraction <<= 1
		if value >= 1<<32 {
			value >>= 1
			fraction++
		}
	}
	return whole*256 + fraction
}

// literalPrices は先頭8KiBの重複を除いたsampleから、literalのbit費用とprefix幅を選ぶ。
func literalPrices(body []byte) ([256]int, uint64) {
	sample := body[:min(len(body), 8192)]
	var history [1024]uint16
	var counts [256]int
	total, i := 0, 0
	for i+8 <= len(sample) {
		value := binary.LittleEndian.Uint64(sample[i : i+8])
		key := uint32((value&0xffffffffffff)*0x9e3779b185ebca87>>32) >> 22
		p := int(history[key]) - 1
		history[key] = uint16(i + 1)
		if p >= 0 && binary.LittleEndian.Uint32(sample[p:p+4]) == uint32(value) {
			i += matchLength(sample, p, i, len(sample), 4)
		} else {
			counts[sample[i]]++
			total++
			i++
		}
	}
	for _, v := range sample[i:] {
		counts[v]++
		total++
	}
	var price [256]int
	information := 0
	for symbol, n := range counts {
		if n > 0 {
			price[symbol] = bitPrice(total, n)
			information += n * price[symbol]
		} else {
			price[symbol] = 12 * 256
		}
	}
	// 平均4.5bit未満では短いprefixの偶然一致が増えるため、7byteで絞る。
	mask := uint64(0xffffffffff)
	if information < total*9*128 {
		mask = 0xffffffffffffff
	}
	return price, mask
}

// worthwhile は短い参照の追加情報がliteralより高くなる候補を落とす。
func worthwhile(body []byte, i, n, offset int, repeat bool, price *[256]int) bool {
	if n >= 16 {
		return true
	}
	literal := 0
	if repeat {
		for _, v := range body[i : i+n] {
			literal += price[v]
			if literal > 7*256 {
				return true
			}
		}
		return false
	}
	for _, v := range body[i : i+n] {
		literal += price[v]
	}
	reference := bits.Len(uint(offset+3)) - 1 + 12
	return literal > reference*256
}

// parse は有界な候補探索と直前offsetの継続でliteralと参照に分ける。
func (e *Encoder) parse(body []byte, begin, end int, repeats [3]int) {
	e.literals = e.literals[:0]
	e.coded = e.coded[:0]
	e.counts = [3][53]int{}
	prices, hashMask := literalPrices(body[begin:end])
	if e.archiveMask != 0 {
		hashMask = e.archiveMask
	}
	anchor := begin
	for i := begin; i+8 <= end; {
		value := binary.LittleEndian.Uint64(body[i : i+8])
		lh := longHash(value, hashMask)
		bucket := &e.long[(lh>>16)&((1<<15)-1)]
		prior := [1]uint64{*bucket}
		*bucket = uint64(lh)<<32 | uint64(i+1)
		fingerprintMiss := uint32(prior[0]>>32) != lh
		if fingerprintMiss {
			repeat := repeats[0]
			if i == anchor {
				repeat = repeats[1]
			}
			if repeat <= 0 || repeat > i || binary.LittleEndian.Uint32(body[i-repeat:i-repeat+4])&0xffffff != uint32(value)&0xffffff {
				i += skipLiterals(body, i, anchor, end, &prices)
				continue
			}
		}
		match, offset := 0, 0
		repeatChosen := false
		candidates := repeats
		if i == anchor {
			candidates = [3]int{repeats[1], repeats[2], repeats[0] - 1}
		}
		repeatCount := len(candidates)
		if fingerprintMiss {
			repeatCount = 1
		}
		for _, repeatOffset := range candidates[:repeatCount] {
			if repeatOffset > 0 && repeatOffset <= i {
				p := i - repeatOffset
				different := binary.LittleEndian.Uint64(body[p:p+8]) ^ value
				if different&0xffffff == 0 {
					n := bits.TrailingZeros64(different) / 8
					if different == 0 {
						n = matchLength(body, p, i, end, 8)
					}
					if n > match {
						match, offset = n, repeatOffset
						repeatChosen = true
						// 小さいrepeat符号を優先し、残るrepeat候補の再比較を省く。
						break
					}
				}
			}
		}
		for _, entry := range prior {
			if entry == 0 || uint32(entry>>32) != lh {
				continue
			}
			lp := int(uint32(entry)) - 1
			if repeatChosen && i-lp == offset {
				continue // repeat候補として比較済みの位置は二度伸ばさない。
			}
			if lp >= 0 && i-lp <= windowLimit {
				different := binary.LittleEndian.Uint64(body[lp:lp+8]) ^ value
				if different&hashMask != 0 {
					continue
				}
				n := bits.TrailingZeros64(different) / 8
				if different == 0 {
					n = matchLength(body, lp, i, end, 8)
				}
				if n > match+2*boolInt(repeatChosen) || n == match && i-lp < offset && !repeatChosen {
					match, offset = n, i-lp
					repeatChosen = false
				}
			}
		}
		if !repeatChosen && match >= 4 && match < 32 && i+9 <= end {
			next := binary.LittleEndian.Uint64(body[i+1 : i+9])
			key := longHash(next, hashMask)
			entry := e.long[(key>>16)&((1<<15)-1)]
			p := int(uint32(entry)) - 1
			if entry != 0 && uint32(entry>>32) == key && p >= 0 && i+1-p <= windowLimit && binary.LittleEndian.Uint64(body[p:p+8])&hashMask == next&hashMask && matchLength(body, p, i+1, end, 0) > match+1 {
				i++
				continue
			}
		}
		if match < 3 || !worthwhile(body, i, match, offset, repeatChosen, &prices) {
			i += skipLiterals(body, i, anchor, end, &prices)
			continue
		}
		// 探索で省いた直前の一致もliteral境界まで戻して参照へ含める。
		for i > anchor && i-offset > 0 && body[i-1] == body[i-offset-1] {
			i--
			match++
		}
		e.emit(body, anchor, i, match, offset, &repeats)
		finish := i + match
		// 一致の末尾を記録し、内部の重複位置を大量に登録しない。

		p := finish - 1
		if p+8 <= end {
			key := longHash(binary.LittleEndian.Uint64(body[p:p+8]), hashMask)
			bucket := &e.long[(key>>16)&((1<<15)-1)]
			*bucket = uint64(key)<<32 | uint64(p+1)
		}
		i, anchor = finish, finish
		// 1〜3byteの変更後が同じoffsetなら、表を探し直さず続きを符号化する。
		for i+9 <= end {
			gap, n := 0, 0
			for candidate := 1; candidate <= 3 && i+candidate+8 <= end; candidate++ {
				p := i + candidate - repeats[0]
				if p < 0 {
					continue
				}
				different := binary.LittleEndian.Uint64(body[i+candidate:i+candidate+8]) ^ binary.LittleEndian.Uint64(body[p:p+8])
				if different&0xffffff != 0 {
					continue
				}
				match := bits.TrailingZeros64(different) / 8
				if different == 0 {
					match = matchLength(body, p, i+candidate, end, 8)
				}
				if worthwhile(body, i+candidate, match, repeats[0], true, &prices) {
					gap, n = candidate, match
					break
				}
			}
			if gap == 0 {
				break
			}
			// 直前offsetの継続をそのまま符号化し、repeat状態は変えない。
			e.literals = append(e.literals, body[i:i+gap]...)
			ml, width, extra := matchLengthCode(n)
			c := sequenceCode{symbol: [3]uint8{uint8(gap), 0, uint8(ml)}, width: uint8(width), extra: uint64(extra)}
			e.coded = append(e.coded, c)
			e.counts[0][gap]++
			e.counts[1][0]++
			e.counts[2][ml]++
			finish = i + gap + n
			for _, p := range [2]int{i + gap, finish - 1} {
				if p+8 <= end {
					key := longHash(binary.LittleEndian.Uint64(body[p:p+8]), hashMask)
					bucket := &e.long[(key>>16)&((1<<15)-1)]
					*bucket = uint64(key)<<32 | uint64(p+1)
				}
			}
			i, anchor = finish, finish
		}
	}
	e.literals = append(e.literals, body[anchor:end]...)
	e.nextRepeats = repeats
}

// boolInt は一致候補の比較費用を小さな整数にする。
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// skipLiterals は高価なbyteを飛ばさず、長いliteral区間だけ探索間隔を広げる。
func skipLiterals(body []byte, i, anchor, end int, prices *[256]int) int {
	step := min(16, 1+(i-anchor)/16)
	if prices[body[i]] > 5*256 {
		return 1
	}
	for n := 1; n < step && i+n < end; n++ {
		if prices[body[i+n]] > 5*256 {
			return n
		}
	}
	return step
}

// emit はliteralと参照の符号・頻度を一度だけ記録し、repeat状態を進める。
func (e *Encoder) emit(body []byte, anchor, i, n, offset int, repeats *[3]int) {
	e.literals = append(e.literals, body[anchor:i]...)
	c := codes(sequence{i - anchor, n, offset}, repeats)
	e.coded = append(e.coded, c)
	for j, v := range c.symbol {
		e.counts[j][v]++
	}
}
