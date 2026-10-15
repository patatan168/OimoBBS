// 公開形式の状態遷移から符号化表を構成する。外部実装の表やコードは使用しない。
package zstdencode

import (
	"encoding/binary"
	"math/bits"
)

// bitWriter は下位bitから書き、末尾flagで逆順読み出しの開始位置を示す。
type bitWriter struct {
	data []byte
	word uint64
	used uint
}

// put は32bit以下の値を共通の64bit出力へ渡す。
func (w *bitWriter) put(value uint32, count uint) { w.putWide(uint64(value), count) }

// putWide は54bit以下の値を詰め、作業wordをまたぐ分だけ次へ繰り越す。
func (w *bitWriter) putWide(value uint64, count uint) {
	// usedは0〜63。countが54以下なので繰越し側のshiftも1〜63に収まる。
	word := w.word | value<<(w.used&63)
	used := w.used + count
	if used >= 64 {
		w.data = binary.LittleEndian.AppendUint64(w.data, word)
		w.word = value >> ((64 - w.used) & 63)
		w.used = used - 64
	} else {
		w.word = word
		w.used = used
	}
}
func (w *bitWriter) finish() []byte { w.put(1, 1); return w.align() }
func (w *bitWriter) align() []byte {
	for w.used > 0 {
		w.data = append(w.data, byte(w.word))
		w.word >>= 8
		if w.used > 8 {
			w.used -= 8
		} else {
			w.used = 0
		}
	}
	return w.data
}

// entropyTable はsymbolと次状態の直接indexで、前状態とbit幅を16bitで引く。
type entropyTable struct {
	log    uint
	first  []uint16
	arena  []uint16
	header []byte
	single int
}

// entropyWork は最大53symbol・512状態までの作業表をworker内で再利用する。
// 次の構築で開始状態とheaderも上書きするため、使用中の表ごとに一つ必要。
type entropyWork struct {
	norm      [53]int
	next      [53]int
	positions [512]int
	first     [53]uint16
	header    [64]byte
	arena     []uint16
}

// distribution は全出現symbolに最低1状態を割り当て、残りを頻度に比例して配分する。
func distribution(counts []int, log uint) []int {
	return distributionInto(counts, log, make([]int, len(counts)))
}

// distributionInto は正規化用の作業配列を初期化して使う。
func distributionInto(counts []int, log uint, norm []int) []int {
	clear(norm)
	total := 0
	for _, n := range counts {
		total += n
	}
	size := 1 << log
	assigned := 0
	for i, n := range counts {
		if n > 0 {
			norm[i] = max(1, n*size/total)
			assigned += norm[i]
		}
	}
	for assigned > size {
		best := -1
		for i, n := range norm {
			if n > 1 && (best < 0 || n*total-counts[i]*size > norm[best]*total-counts[best]*size) {
				best = i
			}
		}
		norm[best]--
		assigned--
	}
	for assigned < 1<<log {
		best := -1
		for i, n := range counts {
			if n > 0 && (best < 0 || n*norm[best] > counts[best]*norm[i]) {
				best = i
			}
		}
		norm[best]++
		assigned++
	}
	return norm
}

// describeDistributionInto は表のheader領域を再利用する。
func describeDistributionInto(norm []int, log uint, buffer []byte) []byte {
	w := bitWriter{data: buffer[:0]}
	w.put(uint32(log-5), 4)
	remaining := 1 << log
	for i := 0; remaining > 0; i++ {
		value := norm[i] + 1
		width := uint(bits.Len(uint(remaining + 1)))
		short := (1 << width) - 1 - (remaining + 1)
		if value < short {
			w.put(uint32(value), width-1)
		} else {
			encoded := value
			if encoded >= 1<<(width-1) {
				encoded += short
			}
			w.put(uint32(encoded), width)
		}
		remaining -= norm[i]
		if norm[i] == 0 {
			run := 0
			for i+run+1 < len(norm) && norm[i+run+1] == 0 {
				run++
			}
			i += run
			for run >= 3 {
				w.put(3, 2)
				run -= 3
			}
			w.put(uint32(run), 2)
		}
	}
	return w.align()
}

// entropyTableWithWork は頻度と作業表を再利用して復号遷移の逆引きを構成する。
func entropyTableWithWork(counts []int, log uint, work *entropyWork) entropyTable {
	last, present := 0, 0
	for i, n := range counts {
		if n > 0 {
			last = i
			present++
		}
	}
	if present == 1 {
		work.header[0] = byte(last)
		return entropyTable{single: last, header: work.header[:1]}
	}
	counts = counts[:last+1]
	norm := distributionInto(counts, log, work.norm[:len(counts)])
	size := 1 << log
	needed := len(counts) * size
	reuse := work.arena
	if cap(reuse) < needed {
		reuse = make([]uint16, needed)
	} else {
		reuse = reuse[:needed]
	}
	work.arena = reuse
	metadata := work.first[:len(counts)]
	clear(metadata)
	t := entropyTable{log: log, single: -1, first: metadata, arena: reuse, header: describeDistributionInto(norm, log, work.header[:])}
	symbols := work.positions[:size]
	position := 0
	step := size/2 + size/8 + 3
	for symbol, n := range norm {
		for range n {
			symbols[position] = symbol
			position = (position + step) & (size - 1)
		}
	}
	next := work.next[:len(norm)]
	copy(next, norm)
	for state, symbol := range symbols {
		n := next[symbol]
		next[symbol]++
		width := log - uint(bits.Len(uint(n))-1)
		// 最終symbolも最低1bitを要求する状態を選び、weight列の終了を明確にする。
		if width > 0 {
			t.first[symbol] = uint16(state)
		}
		base := (n << width) - size
		packed := uint16(state) | uint16(width)<<10
		for v := base; v < base+1<<width; v++ {
			reuse[symbol*size+v] = packed
		}
	}
	return t
}
func (t *entropyTable) start(symbol int) uint16 {
	if t.single >= 0 {
		return 0
	}
	return t.first[symbol]
}

// advance は次状態を逆引きし、bit列を返す。符号のまとめ書きにも使う。
func (t *entropyTable) advance(symbol int, state uint16) (uint16, uint32, uint) {
	if t.single >= 0 {
		return 0, 0, 0
	}
	// logと幅は9以下。平坦な表で二重のslice参照を省く。
	packed := t.arena[(symbol<<(t.log&63))|int(state)]
	width := uint(packed >> 10)
	return packed & 1023, uint32(state) & ((uint32(1) << (width & 31)) - 1), width
}
func (t *entropyTable) encode(w *bitWriter, symbol int, state uint16) uint16 {
	previous, value, width := t.advance(symbol, state)
	w.put(value, width)
	return previous
}

// encodeWeights は偶数・奇数位置を2状態で逆順に符号化する。
func encodeWeights(weights []byte, work *entropyWork) []byte {
	var counts [12]int
	for _, v := range weights {
		counts[v]++
	}
	table := entropyTableWithWork(counts[:], 6, work)
	if table.single >= 0 || len(weights) < 2 {
		return nil
	}
	states := [2]uint16{}
	n := len(weights)
	states[(n-1)%2] = table.start(int(weights[n-1]))
	states[(n-2)%2] = table.start(int(weights[n-2]))
	w := bitWriter{}
	for i := n - 3; i >= 0; i-- {
		states[i%2] = table.encode(&w, int(weights[i]), states[i%2])
	}
	w.put(uint32(states[1]), table.log)
	w.put(uint32(states[0]), table.log)
	return append(table.header, w.finish()...)
}
