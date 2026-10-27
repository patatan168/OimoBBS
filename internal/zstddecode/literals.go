// literalの新規Huffman表と4streamを有界に復号し、bit列の余りを拒否する。
package zstddecode

import (
	"encoding/binary"
	"math/bits"
)

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

// decodeBlockLiterals は未使用出力の末尾へliteralを置き、専用の作業配列確保を省く。
// 呼出元は各sequenceの実行前に、未消費literalと書込範囲の非重複を検査する。
func decodeBlockLiterals(data, out []byte, size int) ([]byte, int, error) {
	var scratch []byte
	if len(data) >= 5 && data[0]&15 == 14 {
		n := int(binary.LittleEndian.Uint32(data)>>4) & ((1 << 18) - 1)
		if n > size-len(out) {
			return nil, 0, ErrInvalid
		}
		scratch = out[:size][size-n:]
	}
	return decodeLiterals(data, &scratch)
}

// decodeLiterals はraw形式または新規表付き4stream形式を受け付ける。
// scratchは呼出元の作業領域を優先し、返却literalをすべて消費してから次を読む。
func decodeLiterals(data []byte, scratch *[]byte) ([]byte, int, error) {
	if len(data) < 3 {
		return nil, 0, ErrInvalid
	}
	mode := data[0] & 15
	if mode == 12 {
		n := (int(data[0]) | int(data[1])<<8 | int(data[2])<<16) >> 4
		if n > blockSize || n > len(data)-3 {
			return nil, 0, ErrInvalid
		}
		return data[3 : 3+n], 3 + n, nil
	}
	if mode != 14 || len(data) < 5 {
		return nil, 0, ErrInvalid
	}
	var header uint64
	for i := range 5 {
		header |= uint64(data[i]) << uint(8*i)
	}
	size := int(header>>4) & ((1 << 18) - 1)
	stored := int(header >> 22)
	if size > blockSize || size < 4 || stored > len(data)-5 {
		return nil, 0, ErrInvalid
	}
	payload := data[5 : 5+stored]
	var tableCells [2048]huffmanCell
	table, depth, used, err := huffmanTable(payload, tableCells[:])
	if err != nil {
		return nil, 0, err
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
	return out, 5 + stored, nil
}
