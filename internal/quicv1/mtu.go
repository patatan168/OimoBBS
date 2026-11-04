// PING/PADDINGのACKで確認したUDPサイズだけを使用し、probe損失では輻輳窓を下げない。
package quicv1

import "time"

// maybeProbeMTU は最大1452byteまで段階的に探索する。接続元検証・handshake後だけ実行する。
func (c *Conn) maybeProbeMTU(now time.Time) {
	if !c.handshakeDone || c.mtuProbePending || c.mtuProbeAt.IsZero() || now.Before(c.mtuProbeAt) || c.mtuFailures >= 3 {
		return
	}
	target := min(c.peerMaxUDP, 1452)
	if c.mtu < 1350 {
		target = min(target, 1350)
	}
	if target <= c.mtu {
		c.mtuProbeAt = time.Time{}
		return
	}
	if c.recovery.inFlight+target > min(c.recovery.cwnd, 1<<20) {
		c.mtuProbeAt = now.Add(time.Millisecond)
		return
	}
	s := &c.spaces[spaceApplication]
	pnSize := 2
	if s.next-s.largestAcked >= 1<<15 {
		pnSize = 4
	}
	payload := make([]byte, target-(1+len(c.peerID)+pnSize+16))
	payload[0] = 1
	pn := s.next
	if err := c.transmit(spaceApplication, payload, []byte{1}, now, true); err != nil {
		c.mtuFailures = 3
		return
	}
	p := s.sent[pn]
	p.mtuProbe = target
	s.sent[pn] = p
	c.mtuProbePending = true
}
func (c *Conn) ackMTU(size int, now time.Time) {
	if size <= 0 {
		return
	}
	c.setMTU(max(c.mtu, size))
	c.mtuProbePending = false
	c.mtuFailures = 0
	c.mtuProbeAt = now
}
func (c *Conn) lostMTU(now time.Time) {
	c.mtuProbePending = false
	c.mtuFailures++
	c.mtuProbeAt = now.Add(250 * time.Millisecond)
}

// splitFrames は縮小したMTUで再送できる単位へ、不変な送信frameを分解する。
func splitFrames(data []byte, chunk int) ([][]byte, error) {
	var result [][]byte
	r := wireReader{data: data}
	for r.left() > 0 {
		start := r.pos
		kind, err := r.integer()
		if err != nil {
			return nil, err
		}
		if kind == 0xe || kind == 0xf {
			id, err := r.integer()
			if err != nil {
				return nil, err
			}
			offset, err := r.integer()
			if err != nil {
				return nil, err
			}
			payload, err := r.blob()
			if err != nil {
				return nil, err
			}
			if len(payload) == 0 {
				result = append(result, data[start:r.pos])
				continue
			}
			for len(payload) > 0 {
				n := min(len(payload), chunk)
				k := uint64(0xe)
				if kind&1 != 0 && n == len(payload) {
					k++
				}
				frame := appendVarint(make([]byte, 0, n+25), k)
				frame = appendVarint(frame, id)
				frame = appendVarint(frame, offset)
				frame = appendVarint(frame, uint64(n))
				frame = append(frame, payload[:n]...)
				result = append(result, frame)
				offset += uint64(n)
				payload = payload[n:]
			}
			continue
		}
		integers := 0
		switch kind {
		case 1, 0x1e:
		case 4:
			integers = 3
		case 5, 0x11:
			integers = 2
		case 0x10, 0x12, 0x13, 0x19:
			integers = 1
		case 0x1b:
			if _, err = r.take(8); err != nil {
				return nil, err
			}
		case 6:
			if _, err = r.integer(); err != nil {
				return nil, err
			}
			if _, err = r.blob(); err != nil {
				return nil, err
			}
		default:
			return nil, protocolError(1, 0, "unsupported retransmission frame")
		}
		for range integers {
			if _, err = r.integer(); err != nil {
				return nil, err
			}
		}
		result = append(result, data[start:r.pos])
	}
	return result, nil
}

// shrinkMTU は経路のblack holeを検知した場合に基準サイズへ戻し、新規探索を止める。
func (c *Conn) shrinkMTU() {
	c.listener.mtuFallbacks.Add(1)
	c.setMTU(1200)
	c.mtuFailures = 3
	c.mtuProbeAt = time.Time{}
	c.mtuProbePending = false
}

// setMTU はpacket番号4byte・最大offset8byteまでを含め、送信可能な本文長を計算する。
// CID長の変更時も更新し、固定の大きな余白によって64KiB本文が余分なpacketへ分割されるのを避ける。
func (c *Conn) setMTU(size int) {
	c.mtu = size
	c.chunkSize.Store(int32(size - (1 + len(c.peerID) + 4 + 16 + 1 + 8 + 8 + 2)))
	c.mtuSnapshot.Store(int32(size))
}

// scheduleMTU は再利用する接続か大きい転送だけを探索し、単発の小さい応答にprobeを加えない。
func (c *Conn) scheduleMTU() {
	if c.handshakeDone && !c.mtuProbePending && c.mtuProbeAt.IsZero() && c.mtuFailures < 3 && c.mtu < min(c.peerMaxUDP, 1452) && (c.nextPeerBidi >= 2 || c.txTotal >= 32<<10) {
		c.mtuProbeAt = time.Now()
	}
}
