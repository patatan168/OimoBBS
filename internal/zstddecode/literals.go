// literalの新規Huffman表と4streamを有界に復号し、bit列の余りを拒否する。
package zstddecode

import (
	"encoding/binary"
	"math/bits"
)

type huffmanCell struct {
	symbol byte
	width  int
}

// weights は最大255個の明示weightを復元し、省略された最後のweightを検査する。
func weights(data []byte) ([]int, int, error) {
	if len(data) == 0 {
		return nil, 0, ErrInvalid
	}
	header := int(data[0])
	at := 1
	var values []int
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
		table, used, err := readTable(data[at:at+header], 12, 6)
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
			values = append(values, cell.symbol)
			if cell.width > b.position {
				if b.position != 0 {
					return nil, 0, ErrInvalid
				}
				other, err := table.cell(states[1-turn])
				if err != nil {
					return nil, 0, err
				}
				values = append(values, other.symbol)
				break
			}
			states[turn] = cell.base + int(b.reverse(cell.width))
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
func huffmanTable(data []byte) ([]huffmanCell, int, int, error) {
	weights, used, err := weights(data)
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
	table := make([]huffmanCell, 1<<uint(depth))
	position := 0
	for w := 1; w <= depth; w++ {
		for symbol, weight := range weights {
			if weight == w {
				n := 1 << uint(w-1)
				if n > len(table)-position {
					return nil, 0, 0, ErrInvalid
				}
				for range n {
					table[position] = huffmanCell{byte(symbol), depth + 1 - w}
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

// decodeLiterals は独自圧縮器のraw形式または新規表付き4stream形式を受け付ける。
func decodeLiterals(data []byte) ([]byte, int, error) {
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
	table, depth, used, err := huffmanTable(payload)
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
	out := make([]byte, 0, size)
	chunk := (size + 3) / 4
	for stream, n := range lengths {
		if n <= 0 || n > len(payload)-at {
			return nil, 0, ErrInvalid
		}
		b, err := reverseStream(payload[at : at+n])
		if err != nil {
			return nil, 0, err
		}
		at += n
		count := min(chunk, size-stream*chunk)
		if count < 0 {
			return nil, 0, ErrInvalid
		}
		for range count {
			width := min(depth, b.position)
			value := b.extract(b.position-width, width) << uint(depth-width)
			cell := table[value]
			if cell.width <= 0 || cell.width > b.position || b.invalid {
				return nil, 0, ErrInvalid
			}
			b.position -= cell.width
			out = append(out, cell.symbol)
		}
		if b.position != 0 {
			return nil, 0, ErrInvalid
		}
	}
	if len(out) != size || at != len(payload) {
		return nil, 0, ErrInvalid
	}
	return out, 5 + stored, nil
}
