// literalの頻度から深さ11以内のprefix符号を作り、本文長に合うstream数で送信する。
package zstdencode

import "slices"

// huffmanCode は幅11bit以内の符号を8byteに収め、頻繁なlookupの領域を小さくする。
type huffmanCode struct {
	value uint32
	width uint8
}
type huffmanNode struct{ frequency, symbol, left, right int }

// huffmanLengths は昇順のleafとmerge済nodeの2列から最小の組を選ぶ。
func huffmanLengths(counts [256]int, floor int) [256]uint {
	var ordered [256]uint64
	leafValues := ordered[:0]
	for symbol, n := range counts {
		if n > 0 {
			leafValues = append(leafValues, uint64(max(n, floor))<<8|uint64(symbol))
		}
	}
	// 頻度とsymbolを一つの整数にすると、大きいnodeの移動と比較callbackが不要になる。
	slices.Sort(leafValues)
	var storage [511]huffmanNode
	nodes := storage[:0]
	for _, v := range leafValues {
		nodes = append(nodes, huffmanNode{int(v >> 8), int(v & 255), -1, -1})
	}
	leaves := len(nodes)
	leaf, branch := 0, leaves
	take := func() int {
		if leaf < leaves && (branch >= len(nodes) || nodes[leaf].frequency <= nodes[branch].frequency) {
			n := leaf
			leaf++
			return n
		}
		n := branch
		branch++
		return n
	}
	for len(nodes) < 2*leaves-1 {
		a, b := take(), take()
		nodes = append(nodes, huffmanNode{nodes[a].frequency + nodes[b].frequency, -1, a, b})
	}
	var lengths [256]uint
	var visit func(int, uint)
	visit = func(i int, depth uint) {
		if nodes[i].symbol >= 0 {
			lengths[nodes[i].symbol] = depth
			return
		}
		visit(nodes[i].left, depth+1)
		visit(nodes[i].right, depth+1)
	}
	if leaves > 1 {
		visit(len(nodes)-1, 0)
	}
	return lengths
}

// huffmanDescription は自前の頻度・treeを使い、公開形式のweight順で符号を割り当てる。
func huffmanDescription(raw []byte, work *entropyWork) ([]byte, [256]huffmanCode) {

	var counts, second [256]int
	i := 0
	// 独立した2組で頻度を数え、同じ文字が続くときの加算待ちを重ねる。
	for ; i+3 < len(raw); i += 4 {
		counts[raw[i]]++
		second[raw[i+1]]++
		counts[raw[i+2]]++
		second[raw[i+3]]++
	}
	for _, v := range raw[i:] {
		counts[v]++
	}
	for symbol, n := range second {
		counts[symbol] += n
	}
	var lengths [256]uint
	depth := uint(0)
	for floor := 1; ; floor *= 2 {
		lengths = huffmanLengths(counts, floor)
		depth = 0
		for _, v := range lengths {
			depth = max(depth, v)
		}
		if depth <= 11 {
			break
		}
	}
	var codes [256]huffmanCode
	if depth == 0 {
		return nil, codes
	}
	last := 255
	for counts[last] == 0 {
		last--
	}
	var weightBuffer [255]byte
	weights := weightBuffer[:last]
	for i := range weights {
		if lengths[i] > 0 {
			weights[i] = byte(depth + 1 - lengths[i])
		}
	}
	var header []byte
	encoded := encodeWeights(weights, work)
	if len(encoded) > 0 && len(encoded) < 128 && (last > 128 || len(encoded) < (last+1)/2) {
		header = append([]byte{byte(len(encoded))}, encoded...)
	} else if last <= 128 {
		header = append(header, byte(127+last))
		for i := 0; i < last; i += 2 {
			v := weights[i] << 4
			if i+1 < last {
				v |= weights[i+1]
			}
			header = append(header, v)
		}
	} else {
		return nil, codes
	}
	var widths [12]uint32
	for _, width := range lengths {
		widths[width]++
	}
	var next [12]uint32
	position := uint32(0)
	for width := depth; width > 0; width-- {
		next[width] = position >> (depth - width)
		position += widths[width] << (depth - width)
	}
	for symbol, width := range lengths {
		if width > 0 {
			codes[symbol] = huffmanCode{next[width], uint8(width)}
			next[width]++
		}
	}

	return header, codes
}

// encodeLiterals は圧縮後が小さい場合だけHuffmanを選ぶ。各streamの入力上限は32KiB。
func encodeLiterals(raw []byte, buffer []byte, work *entropyWork) []byte {
	return encodeLiteralBlock(raw, buffer, work, false)
}

// encodeHTTPLiterals は配信本文の長さに応じてヘッダーとstream数を縮める。
func encodeHTTPLiterals(raw []byte, buffer []byte, work *entropyWork) []byte {
	return encodeLiteralBlock(raw, buffer, work, true)
}

// encodeLiteralBlock はHuffman表を一度だけ作り、縮まなければrawへ戻す。
// 保存では従来の5byteヘッダーと4streamを維持する。
func encodeLiteralBlock(raw []byte, buffer []byte, work *entropyWork, compact bool) []byte {
	if len(raw) < 128 {
		return rawLiteralBlock(raw, buffer, compact)
	}
	header, codes := huffmanDescription(raw, work)
	if header == nil {
		return rawLiteralBlock(raw, buffer, compact)
	}
	format, prefix, width, streams, jumpBytes := uint64(3), 5, uint(18), 4, 6
	if compact {
		if len(raw) < 1024 {
			format, prefix, width, streams, jumpBytes = 0, 3, 10, 1, 0
		} else if len(raw) < 16384 {
			format, prefix, width = 2, 4, 14
		}
	}
	data := append(buffer[:0], make([]byte, prefix+len(header)+jumpBytes)...)
	copy(data[prefix:], header)
	jump := prefix + len(header)
	chunk := (len(raw) + streams - 1) / streams
	for stream := range streams {
		begin, end := min(stream*chunk, len(raw)), min((stream+1)*chunk, len(raw))
		start := len(data)
		w := bitWriter{data: data}
		i := end - 1
		for ; i-3 >= begin; i -= 4 {
			a, b, c, d := codes[raw[i]], codes[raw[i-1]], codes[raw[i-2]], codes[raw[i-3]]
			value := uint64(a.value) | uint64(b.value)<<(a.width&63) | uint64(c.value)<<((a.width+b.width)&63) | uint64(d.value)<<((a.width+b.width+c.width)&63)
			w.putWide(value, uint(a.width+b.width+c.width+d.width))
		}
		for ; i >= begin; i-- {
			code := codes[raw[i]]
			w.put(code.value, uint(code.width))
		}
		data = w.finish()
		size := len(data) - start
		if streams == 4 && stream < 3 {
			data[jump+stream*2] = byte(size)
			data[jump+stream*2+1] = byte(size >> 8)
		}
	}
	rawPrefix := 3
	if compact {
		rawPrefix = rawLiteralHeaderSize(len(raw))
	}
	if len(data) >= len(raw)+rawPrefix {
		return rawLiteralBlock(raw, buffer, compact)
	}
	value := uint64(2) | format<<2 | uint64(len(raw))<<4 | uint64(len(data)-prefix)<<(4+width)
	for i := range prefix {
		data[i] = byte(value >> uint(8*i))
	}
	return data
}

// rawLiterals は非圧縮を選んだ場合だけ本文をcopyする。
func rawLiterals(raw []byte, buffer []byte) []byte {
	header := uint32(len(raw))<<4 | 12
	out := append(buffer[:0], 0, 0, 0)
	out = append(out, raw...)
	out[0] = byte(header)
	out[1] = byte(header >> 8)
	out[2] = byte(header >> 16)
	return out
}

// rawLiteralHeaderSize は配信用raw literalの長さが収まる最短の幅を返す。
func rawLiteralHeaderSize(size int) int {
	if size < 32 {
		return 1
	}
	if size < 4096 {
		return 2
	}
	return 3
}

// rawLiteralBlock は保存用の固定幅か、配信用の短い長さヘッダーを選ぶ。
func rawLiteralBlock(raw, buffer []byte, compact bool) []byte {
	if !compact {
		return rawLiterals(raw, buffer)
	}
	width := rawLiteralHeaderSize(len(raw))
	value := uint32(len(raw))<<4 | 12
	if width == 1 {
		value = uint32(len(raw)) << 3
	} else if width == 2 {
		value = uint32(len(raw))<<4 | 4
	}
	out := append(buffer[:0], make([]byte, width)...)
	for i := range width {
		out[i] = byte(value >> uint(8*i))
	}
	return append(out, raw...)
}
