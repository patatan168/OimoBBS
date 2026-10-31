// literalの新規Huffman表と1/4streamを有界に復号し、bit列の余りを拒否する。
package zstddecode

import (
	"encoding/binary"
	"math/bits"
)

// 符号表の構築比率が高い小frameだけ専用経路を使う。
const compactFrameLimit = 32 << 10

type huffmanCell struct {
	symbol byte
	width  uint8
}

// weights は最大255個の明示weightを復元し、省略された最後のweightを検査する。
// bufferは呼出元の作業領域で、省略weightを含む最大256個を保持する。
func weights(data []byte, buffer []int) ([]int, int, error) {
	if len(data) == 0 {
		return nil, 0, ErrInvalid
	}
	header := int(data[0])
	at := 1
	values := buffer[:0]
	if header >= 128 {
		count := header - 127
		used := (count + 1) / 2
		if len(data)-at < used {
			return nil, 0, ErrInvalid
		}
		for i := range count {
			v := data[at+i/2]
			if i%2 == 0 {
				v >>= 4
			} else {
				v &= 15
			}
			values = append(values, int(v))
		}
		at += used
	} else {
		if header == 0 || header > len(data)-at {
			return nil, 0, ErrInvalid
		}
		var cells [64]fseCell
		table, used, err := readTableInto(data[at:at+header], 12, 6, cells[:])
		if err != nil {
			return nil, 0, err
		}
		b, err := reverseStream(data[at+used : at+header])
		if err != nil {
			return nil, 0, err
		}
		states := [2]int{int(b.reverse(table.log)), int(b.reverse(table.log))}
		for turn := 0; ; turn = 1 - turn {
			cell, err := table.cell(states[turn])
			if err != nil || b.invalid || len(values) >= 254 {
				return nil, 0, ErrInvalid
			}
			values = append(values, int(cell.symbol))
			if int(cell.width) > b.position {
				if b.position != 0 {
					return nil, 0, ErrInvalid
				}
				other, err := table.cell(states[1-turn])
				if err != nil {
					return nil, 0, err
				}
				values = append(values, int(other.symbol))
				break
			}
			states[turn] = int(cell.base) + int(b.reverse(int(cell.width)))
		}
		at += header
	}
	total := 0
	for _, w := range values {
		if w < 0 || w > 11 {
			return nil, 0, ErrInvalid
		}
		if w > 0 {
			total += 1 << uint(w-1)
		}
	}
	if total == 0 {
		return nil, 0, ErrInvalid
	}
	depth := bits.Len(uint(total))
	missing := (1 << uint(depth)) - total
	if depth > 11 || missing == 0 || missing&(missing-1) != 0 {
		return nil, 0, ErrInvalid
	}
	values = append(values, bits.Len(uint(missing)))
	return values, at, nil
}

// huffmanTable はweightの順序から最大2048状態のprefix表を作る。
// tableは呼出元の作業領域を優先し、有効な範囲の全cellを上書きする。
func huffmanTable(data []byte, table []huffmanCell) ([]huffmanCell, int, int, error) {
	var weightBuffer [256]int
	weights, used, err := weights(data, weightBuffer[:0])
	if err != nil {
		return nil, 0, 0, err
	}
	total := 0
	for _, w := range weights {
		if w > 0 {
			total += 1 << uint(w-1)
		}
	}
	depth := bits.Len(uint(total)) - 1
	size := 1 << uint(depth)
	if cap(table) < size {
		table = make([]huffmanCell, size)
	} else {
		table = table[:size]
	}
	position := 0
	for w := 1; w <= depth; w++ {
		for symbol, weight := range weights {
			if weight == w {
				n := 1 << uint(w-1)
				if n > len(table)-position {
					return nil, 0, 0, ErrInvalid
				}
				for range n {
					table[position] = huffmanCell{byte(symbol), uint8(depth + 1 - w)}
					position++
				}
			}
		}
	}
	if position != len(table) {
		return nil, 0, 0, ErrInvalid
	}
	return table, depth, used, nil
}

// huffmanCompactTable は小さいframe向けに記号を一度だけ走査して同じprefix表を作る。
func huffmanCompactTable(data []byte, table []huffmanCell) ([]huffmanCell, int, int, error) {
	var weightBuffer [256]int
	weights, used, err := weights(data, weightBuffer[:0])
	if err != nil {
		return nil, 0, 0, err
	}
	total := 0
	var frequencies [12]int
	for _, w := range weights {
		if w > 0 {
			total += 1 << uint(w-1)
			frequencies[w]++
		}
	}
	depth := bits.Len(uint(total)) - 1
	size := 1 << uint(depth)
	if cap(table) < size {
		table = make([]huffmanCell, size)
	} else {
		table = table[:size]
	}
	var next [12]int
	position := 0
	for weight := 1; weight <= depth; weight++ {
		next[weight] = position
		position += frequencies[weight] << uint(weight-1)
	}
	if position != size {
		return nil, 0, 0, ErrInvalid
	}
	// 幅別の開始位置を先に決め、各symbolを一度だけ走査する。
	for symbol, weight := range weights {
		if weight == 0 {
			continue
		}
		start := next[weight]
		count := 1 << uint(weight-1)
		if count > len(table)-start {
			return nil, 0, 0, ErrInvalid
		}
		region := table[start : start+count]
		cell := huffmanCell{byte(symbol), uint8(depth + 1 - weight)}
		for i := range region {
			region[i] = cell
		}
		next[weight] += count
	}

	return table, depth, used, nil
}

// decodeBlockLiterals は未使用出力の末尾へliteralを置き、専用の作業配列確保を省く。
// 呼出元は各sequenceの実行前に、未消費literalと書込範囲の非重複を検査する。
func decodeBlockLiterals(data, out []byte, size int) ([]byte, int, error) {
	h, err := readLiteralHeader(data)
	if err != nil {
		return nil, 0, err
	}
	var scratch []byte
	if h.streams > 0 {
		if h.size > size-len(out) {
			return nil, 0, ErrInvalid
		}
		scratch = out[:size][size-h.size:]
	}
	return decodeLiteralPayload(data, h, &scratch, size <= compactFrameLimit)
}

// decodeLiterals はraw形式と新規表付き1/4stream形式を受け付ける。
// scratchは返却literalをすべて消費してから次のblockへ再利用する。
func decodeLiterals(data []byte, scratch *[]byte) ([]byte, int, error) {
	h, err := readLiteralHeader(data)
	if err != nil {
		return nil, 0, err
	}
	return decodeLiteralPayload(data, h, scratch, h.size <= compactFrameLimit)
}

// decodeLiteralPayload は検査済みの長さに従い、出力先とbit列の完全消費を確認する。
func decodeLiteralPayload(data []byte, h literalHeader, scratch *[]byte, compact bool) ([]byte, int, error) {
	if h.streams == 0 {
		return data[h.prefix : h.prefix+h.size], h.prefix + h.size, nil
	}
	size, stored := h.size, h.stored
	payload := data[h.prefix : h.prefix+stored]

	var tableCells [2048]huffmanCell
	var table []huffmanCell
	var depth, used int
	var err error
	if compact {
		table, depth, used, err = huffmanCompactTable(payload, tableCells[:])
	} else {
		table, depth, used, err = huffmanTable(payload, tableCells[:])
	}
	if err != nil {
		return nil, 0, err
	}
	if h.streams == 1 {
		out := (*scratch)[:0]
		if cap(out) < size {
			out = make([]byte, 0, size)
		}
		*scratch = out
		out = out[:size]
		if compact {
			err = decodeHuffmanSingleStream(payload[used:], out, table, depth)
		} else {
			err = decodeHuffmanStream(payload[used:], out, table, depth)
		}
		if err != nil {
			return nil, 0, err
		}
		return out, h.prefix + stored, nil
	}
	if len(payload)-used < 6 {
		return nil, 0, ErrInvalid
	}
	lengths := [4]int{}
	total := 0
	for i := range 3 {
		lengths[i] = int(binary.LittleEndian.Uint16(payload[used+2*i:]))
		total += lengths[i]
	}
	at := used + 6
	lengths[3] = len(payload) - at - total
	out := (*scratch)[:0]
	if cap(out) < size {
		out = make([]byte, 0, size)
	}
	*scratch = out
	var streams, outputs [4][]byte
	chunk := (size + 3) / 4
	for stream, n := range lengths {
		if n <= 0 || n > len(payload)-at {
			return nil, 0, ErrInvalid
		}
		count := min(chunk, size-stream*chunk)
		if count < 0 {
			return nil, 0, ErrInvalid
		}
		begin := len(out)
		out = out[:begin+count]
		streams[stream], outputs[stream] = payload[at:at+n], out[begin:]
		at += n
	}
	if len(out) != size || at != len(payload) {
		return nil, 0, ErrInvalid
	}
	if err := decodeHuffmanFour(streams, outputs, table, depth); err != nil {
		return nil, 0, err
	}
	return out, h.prefix + stored, nil
}
