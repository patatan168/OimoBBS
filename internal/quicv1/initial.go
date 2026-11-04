// InitialとHandshakeを同じUDP datagramへまとめ、Initialを含むdatagram全体だけを1200byteへpadする。
package quicv1

type initialPacket struct {
	key     *packetKeys
	number  uint64
	payload []byte
	pnSize  int
}

// coalesceInitial はまだ送っていないInitialを最後に暗号化する。同じnonceの異なる暗号文を送らない。
func (c *Conn) coalesceInitial(packets []*packetBuffer) ([]*packetBuffer, error) {
	found := false
	for _, b := range packets {
		if b.initial != nil {
			found = true
			break
		}
	}
	if !found {
		return packets, nil
	}
	result := make([]*packetBuffer, 0, len(packets))
	var absorbed []*packetBuffer
	for i := 0; i < len(packets); {
		first := packets[i]
		meta := first.initial
		if meta == nil {
			result = append(result, first)
			i++
			continue
		}
		end, total := i+1, len(first.data)
		for end < len(packets) {
			next := packets[end]
			if next.initial != nil || len(next.data) == 0 || next.data[0]&0x80 == 0 || total+len(next.data) > 1200 {
				break
			}
			total += len(next.data)
			end++
		}
		header, pnOffset := makePacketHeader(spaceInitial, c.peerID, c.id, meta.number, len(meta.payload), false, meta.pnSize)
		extra := max(0, 1200-total)
		payload := make([]byte, len(meta.payload)+extra)
		copy(payload, meta.payload)
		header, pnOffset = makePacketHeader(spaceInitial, c.peerID, c.id, meta.number, len(payload), false, meta.pnSize)
		encrypted, err := meta.key.sealPacketInto(first.data[:0], header, payload, meta.number, pnOffset)
		if err != nil {
			return nil, err
		}
		delta := len(encrypted) - len(first.data)
		first.data = encrypted
		first.initial = nil
		s := &c.spaces[spaceInitial]
		if p, ok := s.sent[meta.number]; ok {
			p.size += delta
			s.sent[meta.number] = p
			c.recovery.inFlight += delta
		}
		for j := i + 1; j < end; j++ {
			first.data = append(first.data, packets[j].data...)
			absorbed = append(absorbed, packets[j])
		}
		result = append(result, first)
		i = end
	}
	for _, b := range absorbed {
		releasePacket(b)
	}
	return result, nil
}
func releasePacket(b *packetBuffer) {
	b.initial = nil
	if b.owner != nil {
		owner := b.owner
		b.owner = nil
		b.data = nil
		owner.release()
		cipherPackets.Put(b)
		return
	}
	sendBuffers.Put(b)
}
