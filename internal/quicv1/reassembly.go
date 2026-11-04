// 受信offsetの再構成を固定上限内で行い、食い違う再送・最終長の変更を拒否する。
package quicv1

import "bytes"

type segment struct {
	offset uint64
	data   []byte
}
type reassembly struct {
	next, highest   uint64
	parts           []segment
	buffered, limit int
	final           *uint64
}

func (r *reassembly) insert(offset uint64, data []byte, fin bool) (uint64, error) {
	if offset > maxVarint || uint64(len(data)) > maxVarint-offset {
		return 0, protocolError(0x6, 8, "stream offset overflow")
	}
	end := offset + uint64(len(data))
	if r.final != nil && (end > *r.final || fin && end != *r.final) {
		return 0, protocolError(0x6, 8, "inconsistent final size")
	}
	if fin {
		if end < r.highest {
			return 0, protocolError(0x6, 8, "final size below received offset")
		}
		v := end
		r.final = &v
	}
	newly := uint64(0)
	if end > r.highest {
		newly = end - r.highest
	}
	if len(data) == 0 {
		// 空の区間を残すと、後から届く連続dataの先頭に居残って再構成を止める。
		r.highest = max(r.highest, end)
		return newly, nil
	}
	if end <= r.next {
		return newly, nil
	}
	if offset < r.next {
		data = data[r.next-offset:]
		offset = r.next
	}
	// 通常の順序どおりの到着と末尾への断片追加は、既存区間を走査しない。
	if len(r.parts) == 0 || offset >= r.parts[len(r.parts)-1].offset+uint64(len(r.parts[len(r.parts)-1].data)) {
		if len(data) > r.limit-r.buffered || len(r.parts) >= 256 {
			return 0, protocolError(0xd, 8, "receive reassembly budget exhausted")
		}
		r.parts = append(r.parts, segment{offset, bytes.Clone(data)})
		r.buffered += len(data)
		r.highest = max(r.highest, end)
		return newly, nil
	}
	// 重複部分のbyteを照合し、非重複の区間だけを保存する。
	incoming := []segment{{offset, data}}
	for _, old := range r.parts {
		if old.offset >= end || old.offset+uint64(len(old.data)) <= offset {
			continue
		}
		var remainder []segment
		for _, part := range incoming {
			a, b := max(part.offset, old.offset), min(part.offset+uint64(len(part.data)), old.offset+uint64(len(old.data)))
			if a >= b {
				remainder = append(remainder, part)
				continue
			}
			if !bytes.Equal(part.data[a-part.offset:b-part.offset], old.data[a-old.offset:b-old.offset]) {
				return 0, protocolError(0xa, 8, "inconsistent retransmission")
			}
			if part.offset < a {
				remainder = append(remainder, segment{part.offset, part.data[:a-part.offset]})
			}
			if b < part.offset+uint64(len(part.data)) {
				remainder = append(remainder, segment{b, part.data[b-part.offset:]})
			}
		}
		incoming = remainder
	}
	extra := 0
	for _, p := range incoming {
		extra += len(p.data)
	}
	if extra > r.limit-r.buffered || len(r.parts)+len(incoming) > 256 {
		return 0, protocolError(0xd, 8, "receive reassembly budget exhausted")
	}
	for _, p := range incoming {
		copyPart := segment{p.offset, append([]byte(nil), p.data...)}
		i := 0
		for i < len(r.parts) && r.parts[i].offset < copyPart.offset {
			i++
		}
		r.parts = append(r.parts, segment{})
		copy(r.parts[i+1:], r.parts[i:])
		r.parts[i] = copyPart
	}
	r.buffered += extra
	r.highest = max(r.highest, end)
	return newly, nil
}
func (r *reassembly) pop() []byte {
	if len(r.parts) == 0 || r.parts[0].offset != r.next {
		return nil
	}
	part := r.parts[0]
	r.parts[0] = segment{}
	if len(r.parts) == 1 {
		r.parts = r.parts[:0]
	} else {
		r.parts = r.parts[1:]
	}
	r.next += uint64(len(part.data))
	r.buffered -= len(part.data)
	return part.data
}
