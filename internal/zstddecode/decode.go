// Package zstddecode は独自保存圧縮器が生成する辞書なしZstandard frameを有界に復号する。
// raw/RLE block、新規Huffman表、raw literal、RLE/動的FSE列に対応する。
// 辞書・checksum・表再利用・既定FSE表は未対応として拒否し、部分結果を返さない。
package zstddecode

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// ErrInvalid は破損・サイズ超過・対応外の保存frameを表す。
var ErrInvalid = errors.New("invalid or unsupported stored zstd frame")

const maxSize = 1 << 20
const blockSize = 128 << 10

// Decode は期待する展開長を割当前に検査し、単一frameを完全消費したときだけ専有配列を返す。
// 期待長は0〜1MiB。保存側は別途保存CRC・展開CRC・原本署名を検査する。
func Decode(frame []byte, size int) ([]byte, error) {
	return DecodeBounded(frame, size, maxSize)
}

// DecodeBounded は保存先ごとの展開上限を割当前に検査する。上限自体も8MiB+20bytes以内。
// 探索窓は従来と同じ1MiB。単一frameを完全消費した場合だけ専有結果を返す。
func DecodeBounded(frame []byte, size, limit int) ([]byte, error) {
	if limit < 0 || limit > (8<<20)+20 || size < 0 || size > limit || len(frame) < 6 || binary.LittleEndian.Uint32(frame) != 0xfd2fb528 {
		return nil, ErrInvalid
	}
	descriptor := frame[4]
	if descriptor&0x1f != 0 {
		return nil, ErrInvalid
	}
	at := 5
	single := descriptor&32 != 0
	if !single {
		if len(frame) <= at || frame[at] != 0x50 {
			return nil, ErrInvalid
		}
		at++
	}
	flag := descriptor >> 6
	if flag == 0 && !single {
		return nil, ErrInvalid
	}
	width := []int{1, 2, 4, 8}[flag]
	if len(frame) < at+width {
		return nil, ErrInvalid
	}
	var declared uint64
	for i := range width {
		declared |= uint64(frame[at+i]) << uint(i*8)
	}
	if width == 2 {
		declared += 256
	}
	if declared != uint64(size) {
		return nil, ErrInvalid
	}
	at += width
	out := make([]byte, 0, size)
	repeats := [3]int{1, 4, 8}
	for {
		if len(frame)-at < 3 {
			return nil, ErrInvalid
		}
		header := int(frame[at]) | int(frame[at+1])<<8 | int(frame[at+2])<<16
		at += 3
		n, kind, last := header>>3, (header>>1)&3, header&1 != 0
		if n > blockSize || kind == 3 {
			return nil, ErrInvalid
		}
		stored := n
		if kind == 1 {
			stored = 1
		}
		if stored > len(frame)-at {
			return nil, ErrInvalid
		}
		chunk := frame[at : at+stored]
		at += stored
		if kind == 0 || kind == 1 {
			if n > size-len(out) {
				return nil, ErrInvalid
			}
			if kind == 0 {
				out = append(out, chunk...)
			} else {
				for range n {
					out = append(out, chunk[0])
				}
			}
		} else {
			var err error
			out, err = decodeBlock(chunk, out, size, &repeats)
			if err != nil {
				return nil, err
			}
		}
		if last {
			break
		}
	}
	if at != len(frame) || len(out) != size {
		return nil, ErrInvalid
	}
	return out, nil
}

// bitStream は正方向の表headerと逆方向の符号を同じ有界bit抽出で読む。
type bitStream struct {
	data     []byte
	position int
	invalid  bool
}

func (b *bitStream) extract(position, width int) uint32 {
	if width < 0 || width > 32 || position < 0 || position+width > len(b.data)*8 {
		b.invalid = true
		return 0
	}
	if width == 0 {
		return 0
	}
	data := b.data[position/8:]
	shift := uint(position & 7)
	var value uint64
	if len(data) >= 8 {
		value = binary.LittleEndian.Uint64(data)
	} else {
		// 末尾は必要なbyteだけ読む。終端を越える先読みは行わない。
		for i := 0; i < (int(shift)+width+7)/8; i++ {
			value |= uint64(data[i]) << uint(8*i)
		}
	}
	return uint32(value>>shift) & (uint32(1<<uint(width)) - 1)
}
func (b *bitStream) forward(width int) uint32 {
	v := b.extract(b.position, width)
	b.position += width
	return v
}
func (b *bitStream) reverse(width int) uint32 {
	b.position -= width
	return b.extract(b.position, width)
}
func reverseStream(data []byte) (bitStream, error) {
	if len(data) == 0 || data[len(data)-1] == 0 {
		return bitStream{}, ErrInvalid
	}
	return bitStream{data: data, position: (len(data)-1)*8 + bits.Len8(data[len(data)-1]) - 1}, nil
}

// 最大512状態・256symbolの表なので、遷移は4bytes以内に収まる。
type fseCell struct {
	symbol uint8
	width  uint8
	base   uint16
}
type fseTable struct {
	cells  []fseCell
	log    int
	single fseCell
	rle    bool
}

// readTable は独自圧縮器の非負頻度表を読み、最大512状態の復号遷移を構成する。
func readTable(data []byte, symbols, maxLog int) (fseTable, int, error) {
	return readTableInto(data, symbols, maxLog, nil)
}

// readTableInto は呼出元の作業表を優先し、すべてのcellを入力から上書きする。
func readTableInto(data []byte, symbols, maxLog int, cells []fseCell) (fseTable, int, error) {
	if symbols < 1 || symbols > 256 || maxLog < 5 || maxLog > 9 {
		return fseTable{}, 0, ErrInvalid
	}
	b := bitStream{data: data}
	log := int(b.forward(4)) + 5
	if b.invalid || log > maxLog {
		return fseTable{}, 0, ErrInvalid
	}
	size := 1 << uint(log)
	remaining := size
	var counts [256]int
	norm := counts[:symbols]
	index, present := 0, 0
	for remaining > 0 {
		if index >= symbols {
			return fseTable{}, 0, ErrInvalid
		}
		width := bits.Len(uint(remaining + 1))
		short := (1 << uint(width)) - 1 - (remaining + 1)
		value := int(b.forward(width - 1))
		if value >= short {
			value += int(b.forward(1)) << uint(width-1)
			if value >= 1<<uint(width-1) {
				value -= short
			}
		}
		n := value - 1
		if b.invalid || n < 0 || n > remaining {
			return fseTable{}, 0, ErrInvalid
		}
		norm[index] = n
		remaining -= n
		if n > 0 {
			present++
		}
		index++
		if n == 0 {
			for {
				run := int(b.forward(2))
				index += run
				if b.invalid || index >= symbols {
					return fseTable{}, 0, ErrInvalid
				}
				if run < 3 {
					break
				}
			}
		}
	}
	if present < 2 {
		return fseTable{}, 0, ErrInvalid
	}
	if cap(cells) < size {
		cells = make([]fseCell, size)
	} else {
		cells = cells[:size]
	}
	position := 0
	step := size/2 + size/8 + 3
	for symbol, n := range norm {
		for range n {
			cells[position].symbol = uint8(symbol)
			position = (position + step) & (size - 1)
		}
	}
	for i := range cells {
		symbol := cells[i].symbol
		n := norm[symbol]
		norm[symbol]++
		width := log - (bits.Len(uint(n)) - 1)
		cells[i].width = uint8(width)
		cells[i].base = uint16((n << uint(width)) - size)
	}
	return fseTable{cells: cells, log: log}, (b.position + 7) / 8, nil
}

// sequenceTable は単一symbolまたは新規頻度表だけを受理する。
func sequenceTable(data []byte, mode, symbols int) (fseTable, int, error) {
	return sequenceTableInto(data, mode, symbols, nil)
}

// sequenceTableInto はRLEを含む同じ形式検査を行い、動的表だけを作業領域へ構築する。
func sequenceTableInto(data []byte, mode, symbols int, cells []fseCell) (fseTable, int, error) {
	if mode == 1 {
		if len(data) == 0 || int(data[0]) >= symbols {
			return fseTable{}, 0, ErrInvalid
		}
		return fseTable{single: fseCell{symbol: data[0]}, rle: true}, 1, nil
	}
	if mode != 2 {
		return fseTable{}, 0, ErrInvalid
	}
	maxLog := 9
	if symbols == 21 {
		maxLog = 8
	}
	return readTableInto(data, symbols, maxLog, cells)
}
func (t fseTable) cell(state int) (fseCell, error) {
	if t.rle {
		if state != 0 {
			return fseCell{}, ErrInvalid
		}
		return t.single, nil
	}
	if state < 0 || state >= len(t.cells) {
		return fseCell{}, ErrInvalid
	}
	return t.cells[state], nil
}

// lengthValue は形式の段階的な範囲から基準長と追加bit数を計算する。
func lengthValue(code int, match bool) (int, int) {
	if match {
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

// decodeBlock は列を順に実行し、literal・履歴offset・block長を毎回検査する。
func decodeBlock(data, out []byte, size int, repeats *[3]int) ([]byte, error) {
	literals, at, err := decodeBlockLiterals(data, out, size)
	if err != nil {
		return nil, err
	}
	if at >= len(data) {
		return nil, ErrInvalid
	}
	n := int(data[at])
	at++
	if n >= 128 && n < 255 {
		if at >= len(data) {
			return nil, ErrInvalid
		}
		n = (n-128)*256 + int(data[at])
		at++
	} else if n == 255 {
		if len(data)-at < 2 {
			return nil, ErrInvalid
		}
		n = int(binary.LittleEndian.Uint16(data[at:])) + 0x7f00
		at += 2
	}
	start := len(out)
	if n == 0 {
		if at != len(data) || len(literals) > size-len(out) || len(literals) > blockSize {
			return nil, ErrInvalid
		}
		return append(out, literals...), nil
	}
	if n > blockSize/3 || at >= len(data) {
		return nil, ErrInvalid
	}
	modes := data[at]
	at++
	if modes&3 != 0 {
		return nil, ErrInvalid
	}
	var tables [3]fseTable
	var tableCells [3][]fseCell
	if modes != 0x54 { // 3表ともRLEの場合は動的表の領域を初期化しない。
		var cells [3][512]fseCell
		for i := range tableCells {
			tableCells[i] = cells[i][:]
		}
	}
	var singles [3][1]fseCell
	for i, count := range []int{36, 21, 53} {
		var used int
		tables[i], used, err = sequenceTableInto(data[at:], int(modes>>uint(6-2*i)&3), count, tableCells[i])
		if err != nil {
			return nil, err
		}
		at += used
		if at > len(data) {
			return nil, ErrInvalid
		}
		if tables[i].rle {
			singles[i][0] = tables[i].single
			tables[i].cells = singles[i][:]
		}
	}
	b, err := reverseStream(data[at:])
	if err != nil {
		return nil, err
	}
	var states [3]int
	for i := range states {
		states[i] = int(b.reverse(tables[i].log))
	}
	literalAt := 0
	for sequence := 0; sequence < n; sequence++ {
		// 初期状態はlog幅、以後はreadTableで構成した表内遷移。RLEはlog=0の1要素表。
		// 入力bitが不足した場合もreverseは0を返し、直後のb.invalid検査で拒否する。
		cells := [3]fseCell{
			tables[0].cells[states[0]],
			tables[1].cells[states[1]],
			tables[2].cells[states[2]],
		}
		ml, mw := lengthValue(int(cells[2].symbol), true)
		ll, lw := lengthValue(int(cells[0].symbol), false)
		offsetExtra, matchExtra, literalExtra := b.sequenceThree(int(cells[1].symbol), mw, lw)
		offsetValue := (1 << uint(cells[1].symbol)) + int(offsetExtra)
		ml += int(matchExtra)
		ll += int(literalExtra)
		// llは未消費literal以内。match後も全literalが収まる条件で出力上限も同時に検査する。
		remainingLiterals := len(literals) - literalAt
		if b.invalid || ll > remainingLiterals || ml > size-len(out)-remainingLiterals || ll+ml > blockSize-(len(out)-start) {
			return nil, ErrInvalid
		}
		offset := offsetValue - 3
		if offsetValue <= 3 {
			index := offsetValue - 1
			if ll == 0 {
				index++
			}
			if index == 3 {
				offset = repeats[0] - 1
				*repeats = [3]int{offset, repeats[0], repeats[1]}
			} else {
				offset = repeats[index]
				for j := index; j > 0; j-- {
					repeats[j] = repeats[j-1]
				}
				repeats[0] = offset
			}
		} else {
			*repeats = [3]int{offset, repeats[0], repeats[1]}
		}
		out = append(out, literals[literalAt:literalAt+ll]...)
		literalAt += ll
		if offset <= 0 || offset > len(out) || offset > maxSize {
			return nil, ErrInvalid
		}
		out = copyMatch(out, offset, ml)
		if sequence < n-1 {
			llState, mlState, offsetState := b.sequenceThree(int(cells[0].width), int(cells[2].width), int(cells[1].width))
			states[0] = int(cells[0].base) + int(llState)
			states[2] = int(cells[2].base) + int(mlState)
			states[1] = int(cells[1].base) + int(offsetState)
		}
	}
	if b.invalid || b.position != 0 || len(literals)-literalAt > size-len(out) || len(literals)-literalAt > blockSize-(len(out)-start) {
		return nil, ErrInvalid
	}
	return append(out, literals[literalAt:]...), nil
}

// copyMatch は検査済みの履歴を複製する。重複部分は確定済みprefixから倍増して埋める。
// 呼出元はoffset・長さ・出力容量を検査し、再割当なしで完了させる。
func copyMatch(out []byte, offset, length int) []byte {
	start := len(out)
	out = out[:start+length]
	written := copy(out[start:], out[start-offset:start-offset+min(offset, length)])
	for written < length {
		written += copy(out[start+written:], out[start:start+written])
	}
	return out
}
