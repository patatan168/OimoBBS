// RFC 8878のraw・新規Huffman literalの長さとstream数を割当前に検査する。
package zstddecode

// literalHeader は検証済みヘッダーの幅、元長、保存長、stream数。rawのstreamsは0。
type literalHeader struct {
	prefix, size, stored, streams int
}

// readLiteralHeader は配信用の短い形式と従来の保存形式を同じ上限で読む。
// RLE literalと表の再利用は生成しないため、引き続き受け付けない。
func readLiteralHeader(data []byte) (literalHeader, error) {
	if len(data) == 0 {
		return literalHeader{}, ErrInvalid
	}
	format := (data[0] >> 2) & 3
	h := literalHeader{}
	shift := uint(4)
	switch data[0] & 3 {
	case 0:
		h.prefix = [4]int{1, 2, 1, 3}[format]
		if h.prefix == 1 {
			shift = 3
		}
	case 2:
		h.prefix = [4]int{3, 3, 4, 5}[format]
		h.streams = 4
		if format == 0 {
			h.streams = 1
		}
	default:
		return literalHeader{}, ErrInvalid
	}
	if len(data) < h.prefix {
		return literalHeader{}, ErrInvalid
	}
	var value uint64
	for i := range h.prefix {
		value |= uint64(data[i]) << uint(8*i)
	}
	if h.streams == 0 {
		h.size = int(value >> shift)
		h.stored = h.size
	} else {
		width := [4]uint{10, 10, 14, 18}[format]
		h.size = int(value >> 4 & ((1 << width) - 1))
		h.stored = int(value >> (4 + width))
		if h.size < h.streams {
			return literalHeader{}, ErrInvalid
		}
	}
	if h.size > blockSize || h.stored > len(data)-h.prefix {
		return literalHeader{}, ErrInvalid
	}
	return h, nil
}
