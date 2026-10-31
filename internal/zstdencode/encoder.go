// Package zstdencode はRFC 8878の送信用形式を独立実装する。辞書・復号・checksumは扱わない。
package zstdencode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
	"runtime"
	"sync"
)

const blockLimit = 128 << 10
const windowLimit = 1 << 20

type sequence struct{ literal, match, offset int }

// Encoder は一処理枠専用の再利用可能な圧縮器。保存候補の補助workerは最大1個。
// 並列呼出不可。呼出元の本文配列を保持しない。
type Encoder struct {
	archiveMask     uint64
	archiveLog      uint
	optimizeEntropy bool
	shortMatches    bool
	smallHTTP       bool
	long            [1 << 15]uint64
	short           [1 << 12]uint64
	shortPrevious   [1 << 12]uint64
	literals        []byte
	coded           []sequenceCode
	counts          [3][53]int
	nextRepeats     [3]int
	blockBuffer     []byte
	frameBuffer     []byte
	fseWork         [3]entropyWork
	trialWork       entropyWork
	weightWork      entropyWork
	archivePeer     *Encoder
	// blockごとに初期化する短い参照の費用（1/256bit単位）と探索間隔。
	referenceCost  int
	repeatCost     int
	literalSkipMax int
	literalShift   uint
}

// Encode は配信本文ごとに符号表を選び、辞書なし・1MiB window・内容長付きframeを返す。
// 返却配列は次回呼出から独立する。
func (e *Encoder) Encode(body []byte) []byte {
	// 小さいHTTP本文の通常経路は維持し、大きい一様な本文だけ探索を省く。
	if len(body) >= 32<<10 && uniformBody(body) {
		return bytes.Clone(e.uniformFrame(body))
	}
	e.optimizeEntropy = true
	defer func() { e.optimizeEntropy = false }()
	return bytes.Clone(e.encode(body))
}

// encode はworker内だけで使う一時出力を返す。外部へ渡す前に専有コピーを作る。
func (e *Encoder) encode(body []byte) []byte {
	clear(e.long[:])
	// 小さい配信本文だけ3byte一致の直近2候補を調べる。追加領域は32KiBに制限する。
	e.smallHTTP = e.archiveLog == 0 && len(body) <= 32<<10
	e.shortMatches = e.smallHTTP && len(body) >= 512
	if e.shortMatches {
		clear(e.short[:])
		clear(e.shortPrevious[:])
	}
	// 本文長に合う内容長幅を使い、復号の履歴は最大1MiBに制限する。
	result := frameHeader(e.frameBuffer[:0], uint64(len(body)))
	if len(body) == 0 {
		result = append(result, 1, 0, 0)
		e.frameBuffer = result
		return result
	}
	repeats := [3]int{1, 4, 8}
	for begin := 0; begin < len(body); begin += blockLimit {
		end := min(begin+blockLimit, len(body))
		e.parse(body, begin, end, repeats)
		// raw/RLE blockはrepeat履歴を進めない。
		kind, payload := uint32(1), body[begin:begin+1]
		if !e.isRLEBlock(body[begin:end]) {
			compressed, nextRepeats := e.block(repeats)
			e.blockBuffer = compressed
			kind, payload = 2, compressed
			if len(compressed) >= end-begin {
				kind, payload = 0, body[begin:end]
			} else {
				repeats = nextRepeats
			}
		}
		size := len(payload)
		if kind == 1 {
			// RLEのblock長はpayload長ではなく展開長。
			size = end - begin
		}
		header := uint32(size)<<3 | kind<<1
		if end == len(body) {
			header |= 1
		}
		result = append(result, byte(header), byte(header>>8), byte(header>>16))
		result = append(result, payload...)
	}
	e.frameBuffer = result
	return result
}

// ArchiveOptions は保存用の有界な探索量・prefix幅・FSE精度を指定する。
type ArchiveOptions struct {
	HashBytes   int
	AccuracyLog uint
	// OptimizeEntropy は列ごとに精度5〜9（offsetは8まで）の実符号長を比較する。
	OptimizeEntropy bool
}

// EncodeArchive は保存用のprefix幅とFSE精度で圧縮する。入力・探索窓は1MiB以内。
// 配信のEncodeとは別の方針で、返却byteは次回呼出から独立する。
func (e *Encoder) EncodeArchive(body []byte, options ArchiveOptions) ([]byte, error) {
	if len(body) > windowLimit {
		return nil, errors.New("invalid archive compression input")
	}
	return e.EncodeBestArchive(body, []ArchiveOptions{options})
}

// EncodeBestArchive は同じ入力への全候補から最小の専有出力を返す。
// 探索窓は1MiB、入力はWALの8MiBと外枠20bytesまで。候補ごとの返却配列確保を省く。
// 32KiB以上・複数候補・複数CPUでは最大2workerで比較する。並列呼出しは不可。
// 候補が不正なら符号化を始めずerrorを返す。同じ長さなら入力順の先行候補を採用する。
func (e *Encoder) EncodeBestArchive(body []byte, options []ArchiveOptions) ([]byte, error) {
	if len(body) > (8<<20)+20 || len(options) == 0 || len(options) > 4 {
		return nil, errors.New("invalid archive compression input")
	}
	for _, option := range options {
		if (option.HashBytes != 0 && (option.HashBytes < 4 || option.HashBytes > 7)) || option.AccuracyLog < 7 || option.AccuracyLog > 9 {
			return nil, errors.New("invalid archive compression input")
		}
	}
	if uniformBody(body) {
		return bytes.Clone(e.uniformFrame(body)), nil
	}
	options = uniqueArchiveOptions(body, options)
	if len(body) < 32<<10 || len(options) < 2 || runtime.GOMAXPROCS(0) < 2 {
		return e.encodeArchiveCandidates(body, options), nil
	}
	if e.archivePeer == nil {
		e.archivePeer = &Encoder{}
	}
	middle := (len(options) + 1) / 2
	var peer []byte
	var pending sync.WaitGroup
	pending.Go(func() { peer = e.archivePeer.encodeArchiveCandidates(body, options[middle:]) })
	best := e.encodeArchiveCandidates(body, options[:middle])
	pending.Wait()
	if len(peer) < len(best) {
		best = peer
	}
	return best, nil
}

// encodeArchiveCandidates は検査済み候補を同じ作業器で順に比較する。
func (e *Encoder) encodeArchiveCandidates(body []byte, options []ArchiveOptions) []byte {
	defer func() { e.archiveMask = 0; e.archiveLog = 0; e.optimizeEntropy = false }()
	var best []byte
	for _, option := range options {
		e.archiveMask = 0
		if option.HashBytes != 0 {
			e.archiveMask = (uint64(1) << uint(option.HashBytes*8)) - 1
		}
		e.archiveLog = option.AccuracyLog
		e.optimizeEntropy = option.OptimizeEntropy
		candidate := e.encode(body)
		if best == nil || len(candidate) < len(best) {
			best = append(best[:0], candidate...)
		}
	}
	return best
}

// frameHeader はRFC 8878の内容長幅を選び、小本文ではwindow記述も省く。
func frameHeader(buffer []byte, size uint64) []byte {
	buffer = append(buffer, 0x28, 0xb5, 0x2f, 0xfd)
	switch {
	case size <= 255:
		return append(buffer, 0x20, byte(size))
	case size <= 65791:
		return binary.LittleEndian.AppendUint16(append(buffer, 0x60), uint16(size-256))
	case size <= windowLimit:
		return binary.LittleEndian.AppendUint32(append(buffer, 0xa0), uint32(size))
	case size <= 1<<32-1:
		return binary.LittleEndian.AppendUint32(append(buffer, 0x80, 0x50), uint32(size))
	default:
		return binary.LittleEndian.AppendUint64(append(buffer, 0xc0, 0x50), size)
	}
}

// lengthCode は形式の段階的な長さ範囲を計算し、既存実装のlookup表を持たない。
func lengthCode(value int, match bool) (int, uint, uint32) {
	if match {
		if value <= 34 {
			return value - 3, 0, 0
		}
		if value <= 42 {
			return 32 + (value-35)/2, 1, uint32((value - 35) & 1)
		}
		if value <= 50 {
			return 36 + (value-43)/4, 2, uint32((value - 43) & 3)
		}
		if value <= 66 {
			return 38 + (value-51)/8, 3, uint32((value - 51) & 7)
		}
		if value <= 98 {
			return 40 + (value-67)/16, 4, uint32((value - 67) & 15)
		}
		if value <= 130 {
			return 42, 5, uint32(value - 99)
		}
		width := uint(bits.Len(uint(value-3)) - 1)
		return int(width) + 36, width, uint32(value - 3 - (1 << width))
	}
	if value <= 15 {
		return value, 0, 0
	}
	if value <= 23 {
		return 16 + (value-16)/2, 1, uint32((value - 16) & 1)
	}
	if value <= 31 {
		return 20 + (value-24)/4, 2, uint32((value - 24) & 3)
	}
	if value <= 47 {
		return 22 + (value-32)/8, 3, uint32((value - 32) & 7)
	}
	if value <= 63 {
		return 24, 4, uint32(value - 48)
	}
	width := uint(bits.Len(uint(value)) - 1)
	return int(width) + 19, width, uint32(value - (1 << width))
}

type lengthEncoding struct {
	symbol uint8
	width  uint8
	extra  uint16
}

var literalLengths = smallLengthEncodings(false)
var matchLengths = smallLengthEncodings(true)

// smallLengthEncodings は小さい値の符号を形式の計算式から生成し、参照ごとの分岐を減らす。
func smallLengthEncodings(match bool) [256]lengthEncoding {
	var out [256]lengthEncoding
	start := 0
	if match {
		start = 3
	}
	for value := start; value < len(out); value++ {
		symbol, width, extra := lengthCode(value, match)
		out[value] = lengthEncoding{uint8(symbol), uint8(width), uint16(extra)}
	}
	return out
}

// literalLength は小さいliteral長を表で引き、大きい値だけ計算する。
func literalLength(value int) (int, uint, uint32) {
	if value < 256 {
		v := literalLengths[value]
		return int(v.symbol), uint(v.width), uint32(v.extra)
	}
	width := uint(bits.Len(uint(value)) - 1)
	return int(width) + 19, width, uint32(value - (1 << width))
}

// matchLengthCode は小さい参照長を表で引き、大きい値だけ計算する。
func matchLengthCode(value int) (int, uint, uint32) {
	if value < 256 {
		v := matchLengths[value]
		return int(v.symbol), uint(v.width), uint32(v.extra)
	}
	width := uint(bits.Len(uint(value-3)) - 1)
	return int(width) + 36, width, uint32(value - 3 - (1 << width))
}

type sequenceCode struct {
	symbol [3]uint8
	width  uint8
	extra  uint64
}

// codes は長さと直前offsetを符号へ変換し、追加bitを一つの値へまとめる。
func codes(s sequence, repeats *[3]int) sequenceCode {
	var c sequenceCode
	ll, lw, lv := literalLength(s.literal)
	ml, mw, mv := matchLengthCode(s.match)
	if s.literal > 0 && s.offset == repeats[0] {
		return sequenceCode{symbol: [3]uint8{uint8(ll), 0, uint8(ml)}, width: uint8(lw + mw), extra: uint64(lv) | uint64(mv)<<(lw&63)}
	}
	value := offsetValue(s.offset, s.literal, repeats)
	ow := uint(bits.Len(uint(value)) - 1)
	c.symbol = [3]uint8{uint8(ll), uint8(ow), uint8(ml)}
	c.width = uint8(lw + mw + ow)
	c.extra = uint64(lv) | uint64(mv)<<(lw&63) | uint64(value-(1<<ow))<<((lw+mw)&63)
	return c
}

// offsetValue は形式のrepeat参照を選び、直前3offsetを更新する。
func offsetValue(offset, literal int, repeats *[3]int) int {
	value := offset + 3
	for v := 1; v <= 3; v++ {
		index := v - 1
		if literal == 0 {
			index++
		}
		distance := repeats[0] - 1
		if index < 3 {
			distance = repeats[index]
		}
		if distance != offset {
			continue
		}
		value = v
		if index < 3 {
			for j := index; j > 0; j-- {
				repeats[j] = repeats[j-1]
			}
			repeats[0] = distance
		} else {
			*repeats = [3]int{distance, repeats[0], repeats[1]}
		}
		break
	}
	if value > 3 {
		*repeats = [3]int{offset, repeats[0], repeats[1]}
	}
	return value
}

// block はliteralと3種類の参照情報を独立した頻度表で符号化する。
func (e *Encoder) block(repeats [3]int) ([]byte, [3]int) {
	var out []byte
	if e.archiveLog == 0 {
		out = encodeHTTPLiterals(e.literals, e.blockBuffer, &e.weightWork)
	} else {
		out = encodeLiterals(e.literals, e.blockBuffer, &e.weightWork)
	}
	n := len(e.coded)
	if n == 0 {
		return append(out, 0), repeats
	}
	switch {
	case n < 128:
		out = append(out, byte(n))
	case n < 0x7f00:
		out = append(out, byte((n>>8)+128), byte(n))
	default:
		out = append(out, 255, byte(n-0x7f00), byte((n-0x7f00)>>8))
	}
	counts := [3][]int{e.counts[0][:36], e.counts[1][:21], e.counts[2][:53]}
	repeats = e.nextRepeats
	tables := [3]entropyTable{}
	mode := byte(0)
	for i := range tables {
		log := uint(7)
		if e.archiveLog != 0 {
			log = e.archiveLog
		}
		if i == 1 {
			log = min(log, 8)
		} // offset表の形式上限は8bit。
		if e.optimizeEntropy && e.smallHTTP {
			tables[i] = e.bestEntropyTable(counts[i], i)
		} else {
			if e.optimizeEntropy {
				log = e.bestEntropyLog(counts[i], i)
			}
			tables[i] = entropyTableWithWork(counts[i], log, &e.fseWork[i])
		}
		m := byte(2)
		// headerが空の表は標準の定義済み表。
		if len(tables[i].header) == 0 {
			m = 0
		}
		if tables[i].single >= 0 {
			m = 1
		}
		mode |= m << uint(6-2*i)
	}
	e.ensureSequenceLookahead(&tables, counts[2])
	out = append(out, mode)
	for _, t := range tables {
		out = append(out, t.header...)
	}
	last := e.coded[n-1]
	var states [3]uint16
	for i := range states {
		states[i] = tables[i].start(int(last.symbol[i]))
	}
	w := bitWriter{data: out}
	for i := n - 1; i >= 0; i-- {
		c := e.coded[i]
		if i < n-1 {
			var offsetBits, matchBits, literalBits uint32
			var offsetWidth, matchWidth, literalWidth uint
			states[1], offsetBits, offsetWidth = tables[1].advance(int(c.symbol[1]), states[1])
			states[2], matchBits, matchWidth = tables[2].advance(int(c.symbol[2]), states[2])
			states[0], literalBits, literalWidth = tables[0].advance(int(c.symbol[0]), states[0])
			// 各表は9bit以内。3種類をまとめ、ループと可変indexを省く。
			value := offsetBits | matchBits<<(offsetWidth&31) | literalBits<<((offsetWidth+matchWidth)&31)
			w.put(value, offsetWidth+matchWidth+literalWidth)
		}
		w.putWide(c.extra, uint(c.width))
	}
	for _, j := range []int{2, 1, 0} {
		w.put(uint32(states[j]), tables[j].log)
	}
	return w.finish(), repeats
}

// ensureSequenceLookahead は末尾の動的ML表に続くbit列を最低2byteにする。
// Goの独立復号器は表の最終値にも16bitを先読みするため、1byteだけでは拒否される。
func (e *Encoder) ensureSequenceLookahead(tables *[3]entropyTable, counts []int) {
	if tables[0].single < 0 || tables[1].single < 0 || tables[2].single >= 0 || tables[2].log >= 8 || len(tables[2].header) == 0 {
		return
	}
	table := &tables[2]
	bits := int(table.log)
	state := table.start(int(e.coded[len(e.coded)-1].symbol[2]))
	for i := len(e.coded) - 1; i >= 0; i-- {
		bits += int(e.coded[i].width)
		if i < len(e.coded)-1 {
			var width uint
			state, width = table.transition(int(e.coded[i].symbol[2]), state)
			bits += int(width)
		}
		if bits >= 8 {
			return
		}
	}
	tables[2] = entropyTableWithWork(counts, 8, &e.fseWork[2])
}
