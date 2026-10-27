// literalの頻度から深さ11以内のprefix符号を作り、4streamに分けて送信する。
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
	var counts [256]int
	for _, v := range raw {
		counts[v]++
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
	weights := make([]byte, last)
	for i := range weights {
		if lengths[i] > 0 {
			weights[i] = byte(depth + 1 - lengths[i])
		}
	}
	var header []byte
	if last <= 128 {
		header = append(header, byte(127+last))
		for i := 0; i < last; i += 2 {
			v := weights[i] << 4
			if i+1 < last {
				v |= weights[i+1]
			}
			header = append(header, v)
		}
	} else {
		encoded := encodeWeights(weights, work)
		if len(encoded) == 0 || len(encoded) >= 128 {
			return nil, codes
		}
		header = append([]byte{byte(len(encoded))}, encoded...)
	}
	position := uint32(0)
	for width := depth; width > 0; width-- {
		for symbol, n := range lengths {
			if n == width {
				codes[symbol] = huffmanCode{position >> (depth - width), uint8(width)}
				position += 1 << (depth - width)
			}
		}
	}
	return header, codes
}

// encodeLiterals は圧縮後が小さい場合だけHuffmanを選ぶ。各streamの入力上限は32KiB。
func encodeLiterals(raw []byte, buffer []byte, work *entropyWork) []byte {
	if len(raw) < 256 {
		return rawLiterals(raw, buffer)
	}
	header, codes := huffmanDescription(raw, work)
	if header == nil {
		return rawLiterals(raw, buffer)
	}
	data := append(buffer[:0], make([]byte, 5+len(header)+6)...)
	copy(data[5:], header)
	jump := 5 + len(header)
	chunk := (len(raw) + 3) / 4
	for stream := range 4 {
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
		if stream < 3 {
			data[jump+stream*2] = byte(size)
			data[jump+stream*2+1] = byte(size >> 8)
		}
	}
	if len(data) >= len(raw)+3 {
		return rawLiterals(raw, buffer)
	}
	// 18bitの元長・圧縮長を常に使用し、境界で形式を変えない。
	value := uint64(14) | uint64(len(raw))<<4 | uint64(len(data)-5)<<22
	for i := range 5 {
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
