// 認証済みQUIC frameを有界に解析し、packet番号空間・stream方向・flow制約を検証する。
package quicv1

import (
	"bytes"
	"io"
	"time"
)

func (c *Conn) frames(space int, data []byte, now time.Time) (bool, error) {
	r := wireReader{data: data}
	eliciting := false
	frames := 0
	ackFrames := 0
	for r.left() > 0 {
		kind, err := r.integer()
		if err != nil {
			return false, err
		}
		frames++
		if frames > 1200 {
			return false, protocolError(7, kind, "too many frames")
		}
		if kind != 0 && kind != 2 && kind != 3 {
			eliciting = true
		}
		if space != spaceApplication && kind != 0 && kind != 1 && kind != 2 && kind != 3 && kind != 6 && kind != 0x1c {
			return false, protocolError(0xa, kind, "frame in wrong encryption level")
		}
		switch {
		case kind == 0 || kind == 1:
		case kind == 2 || kind == 3:
			ackFrames++
			if ackFrames > 8 {
				return false, protocolError(1, kind, "ACK processing budget exhausted")
			}
			if err := c.acknowledge(space, &r, kind == 3, now); err != nil {
				return false, err
			}
		case kind == 6:
			offset, err := r.integer()
			if err != nil {
				return false, err
			}
			body, err := r.blob()
			if err != nil {
				return false, err
			}
			if err = c.cryptoFrame(space, offset, body); err != nil {
				return false, err
			}
		case kind >= 8 && kind <= 15:
			id, err := r.integer()
			if err != nil {
				return false, err
			}
			offset := uint64(0)
			if kind&4 != 0 {
				offset, err = r.integer()
				if err != nil {
					return false, err
				}
			}
			var body []byte
			if kind&2 != 0 {
				body, err = r.blob()
			} else {
				body, err = r.take(r.left())
			}
			if err != nil {
				return false, err
			}
			if err = c.streamData(id, offset, body, kind&1 != 0); err != nil {
				return false, err
			}
		case kind == 4:
			id, err := r.integer()
			if err != nil {
				return false, err
			}
			code, err := r.integer()
			if err != nil {
				return false, err
			}
			final, err := r.integer()
			if err != nil {
				return false, err
			}
			if err = c.resetStream(id, code, final); err != nil {
				return false, err
			}
		case kind == 5:
			id, err := r.integer()
			if err != nil {
				return false, err
			}
			code, err := r.integer()
			if err != nil {
				return false, err
			}
			s, err := c.peerStream(id, false)
			if err != nil {
				return false, err
			}
			if s != nil {
				s.mu.Lock()
				s.cancel()
				s.writeErr = &StreamError{Code: code, Remote: true}
				s.notifyWrite()
				s.mu.Unlock()
				c.resetWrite(s, code)
			}
		case kind == 0x10:
			value, err := r.integer()
			if err != nil {
				return false, err
			}
			c.peerMaxData = max(c.peerMaxData, value)
		case kind == 0x11:
			id, err := r.integer()
			if err != nil {
				return false, err
			}
			value, err := r.integer()
			if err != nil {
				return false, err
			}
			s, err := c.peerStream(id, false)
			if err != nil {
				return false, err
			}
			if s != nil {
				s.txLimit = max(s.txLimit, value)
			}
		case kind == 0x12 || kind == 0x13:
			value, err := r.integer()
			if err != nil {
				return false, err
			}
			if value > 1<<60 {
				return false, protocolError(4, kind, "stream credit overflow")
			}
			if kind == 0x13 {
				c.peerMaxUni = max(c.peerMaxUni, value)
			}
		case kind == 0x14 || kind == 0x16 || kind == 0x17:
			if _, err := r.integer(); err != nil {
				return false, err
			}
		case kind == 0x15:
			if _, err := r.integer(); err != nil {
				return false, err
			}
			if _, err := r.integer(); err != nil {
				return false, err
			}
		case kind == 0x18:
			if err := c.newPeerCID(&r); err != nil {
				return false, err
			}
		case kind == 0x19:
			seq, err := r.integer()
			if err != nil {
				return false, err
			}
			if seq != 0 {
				return false, protocolError(0xa, kind, "retired unissued CID")
			}
			return false, protocolError(0xa, kind, "retired current destination CID")
		case kind == 0x1a:
			challenge, err := r.take(8)
			if err != nil {
				return false, err
			}
			if !c.allowPathResponse(now) {
				return false, protocolError(1, kind, "path response budget exhausted")
			}
			c.queueFrame(spaceApplication, append([]byte{0x1b}, challenge...), nil, true)
		case kind == 0x1b:
			if _, err := r.take(8); err != nil {
				return false, err
			}
		case kind == 0x1c || kind == 0x1d:
			if _, err := r.integer(); err != nil {
				return false, err
			}
			if kind == 0x1c {
				if _, err := r.integer(); err != nil {
					return false, err
				}
			}
			if _, err := r.blob(); err != nil {
				return false, err
			}
			return false, errClosed
		case kind == 7 || kind == 0x1e:
			return false, protocolError(0xa, kind, "server-only frame received")
		default:
			return false, protocolError(7, kind, "unknown frame type")
		}
	}
	return eliciting, nil
}

func (c *Conn) acknowledge(index int, r *wireReader, ecn bool, now time.Time) error {
	largest, err := r.integer()
	if err != nil {
		return err
	}
	delay, err := r.integer()
	if err != nil {
		return err
	}
	count, err := r.integer()
	if err != nil || count > 256 {
		return protocolError(7, 2, "ACK range count")
	}
	first, err := r.integer()
	if err != nil || first > largest {
		return protocolError(7, 2, "ACK first range")
	}
	s := &c.spaces[index]
	if index == spaceApplication && largest >= c.writePhaseFirst {
		c.writePhaseAcked = true
	}
	if largest >= s.next {
		return protocolError(0xa, 2, "ACK for unsent packet")
	}
	type ackRange struct{ low, high uint64 }
	var scratch [17]ackRange
	ranges := append(scratch[:0], ackRange{largest - first, largest})
	for i := uint64(0); i < count; i++ {
		gap, err := r.integer()
		if err != nil {
			return err
		}
		length, err := r.integer()
		if err != nil {
			return err
		}
		low := ranges[len(ranges)-1].low
		if low < 2 || gap > low-2 {
			return protocolError(7, 2, "ACK gap underflow")
		}
		high := low - gap - 2
		if length > high {
			return protocolError(7, 2, "ACK range underflow")
		}
		ranges = append(ranges, ackRange{high - length, high})
	}
	if ecn {
		for i := 0; i < 3; i++ {
			if _, err := r.integer(); err != nil {
				return err
			}
		}
	}
	if p, ok := s.sent[largest]; ok {
		maxDelay := uint64((time.Second * 60) / time.Microsecond)
		scaled := maxDelay
		if delay <= maxDelay>>c.recovery.peerAckExponent {
			scaled = delay << c.recovery.peerAckExponent
		}
		c.recovery.updateRTT(now.Sub(p.at), time.Duration(scaled)*time.Microsecond, index == spaceApplication)
	}
	acknowledged := false
	rangeIndex := len(ranges) - 1
	for _, pn := range s.sentOrder[s.sentHead:] {
		if pn > largest {
			break
		}
		for rangeIndex >= 0 && pn > ranges[rangeIndex].high {
			rangeIndex--
		}
		if rangeIndex < 0 {
			break
		}
		if pn < ranges[rangeIndex].low {
			continue
		}
		p, ok := s.sent[pn]
		if !ok {
			continue
		}
		delete(s.sent, pn)
		c.recovery.acknowledged(p)
		c.ackMTU(p.mtuProbe, now)
		if p.size > 1200 {
			c.largeLosses = 0
			c.firstLargeLoss = time.Time{}
			c.lastLargeAck = now
		} else {
			c.lastSmallAck = now
		}
		c.ackedFrames(p.frames)
		releaseRefs(p.refs)
		acknowledged = true
	}

	if acknowledged {
		c.recovery.ptoCount = 0
	}
	if !s.hasAcked || largest > s.largestAcked {
		s.largestAcked = largest
		s.hasAcked = true
	}
	c.detectLost(index, now)
	return nil
}

type peerCID struct{ id, token []byte }

// newPeerCID は未retireのCIDだけを保持し、sequence番号の増加で履歴を増やさない。
func (c *Conn) newPeerCID(r *wireReader) error {
	seq, err := r.integer()
	if err != nil {
		return err
	}
	retire, err := r.integer()
	if err != nil || retire > seq {
		return protocolError(7, 0x18, "CID retirement order")
	}
	n, err := r.take(1)
	if err != nil || n[0] < 1 || n[0] > 20 {
		return protocolError(7, 0x18, "CID length")
	}
	id, err := r.take(int(n[0]))
	if err != nil {
		return err
	}
	token, err := r.take(16)
	if err != nil {
		return err
	}
	retireOne := func(n uint64) { f := appendVarint(nil, 0x19); f = appendVarint(f, n); c.queue(spaceApplication, f) }
	c.peerRetireFloor = max(c.peerRetireFloor, retire)
	if seq < c.peerRetireFloor {
		retireOne(seq)
		return nil
	}
	for old, entry := range c.peerCIDs {
		if old == seq && (!bytes.Equal(entry.id, id) || len(entry.token) > 0 && !bytes.Equal(entry.token, token)) {
			return protocolError(0xa, 0x18, "CID sequence changed")
		}
		if old != seq && bytes.Equal(entry.id, id) {
			return protocolError(0xa, 0x18, "CID reused")
		}
		if old < c.peerRetireFloor {
			delete(c.peerCIDs, old)
			retireOne(old)
		}
	}
	c.peerCIDs[seq] = peerCID{append([]byte(nil), id...), append([]byte(nil), token...)}
	if len(c.peerCIDs) > 2 {
		return protocolError(9, 0x18, "active CID limit")
	}
	if c.peerCIDSequence < c.peerRetireFloor {
		c.peerCIDSequence = seq
		c.peerID = append(c.peerID[:0], id...)
		if c.mtu >= 1200 {
			c.setMTU(c.mtu)
		}
	}
	return nil
}

func (c *Conn) peerStream(id uint64, receiving bool) (*Stream, error) {
	if !receiving && id&3 == 2 {
		return nil, protocolError(5, 8, "send control on peer unidirectional stream")
	}
	if s := c.streams[id]; s != nil {
		if receiving && id&3 == 3 {
			return nil, protocolError(5, 8, "received data on local unidirectional stream")
		}
		return s, nil
	}
	if id&1 != 0 {
		return nil, protocolError(5, 8, "unknown local stream")
	}
	kind := int((id >> 1) & 1)
	ordinal := id / 4
	if ordinal < c.retired[kind] {
		return nil, nil
	}
	if ordinal >= c.localCredit[kind] {
		return nil, protocolError(4, 8, "stream limit exceeded")
	}
	if _, retired := c.finished[kind][ordinal]; retired {
		return nil, nil
	}
	next := &c.nextPeerBidi
	if kind == 1 {
		next = &c.nextPeerUni
	}
	for *next <= ordinal {
		streamID := *next*4 + uint64(kind*2)
		*next++
		if len(c.streams) >= 38 {
			return nil, protocolError(4, 8, "active stream budget exhausted")
		}
		s := newStream(c, streamID)
		s.txLimit = c.peerBidiLocal
		if kind == 1 {
			s.writeClosed = true
			s.writeErr = io.ErrClosedPipe
			s.txFinalAcked = true
		}
		c.streams[streamID] = s
		queue := c.bidi
		if kind == 1 {
			queue = c.uni
		}
		select {
		case queue <- s:
		default:
			return nil, protocolError(4, 8, "stream acceptance queue exhausted")
		}
	}
	c.scheduleMTU()
	return c.streams[id], nil
}
func (c *Conn) streamData(id, offset uint64, data []byte, fin bool) error {
	s, err := c.peerStream(id, true)
	if err != nil || s == nil {
		return err
	}
	s.mu.Lock()
	end := offset + uint64(len(data))
	if end < offset || end > s.receiveLimit {
		s.mu.Unlock()
		return protocolError(3, 8, "stream flow limit exceeded")
	}
	newly := uint64(0)
	if end > s.rx.highest {
		newly = end - s.rx.highest
	}
	if newly > c.receiveLimit-c.receiveTotal {
		s.mu.Unlock()
		return protocolError(3, 8, "connection flow limit exceeded")
	}
	if s.rxStopped {
		if s.rx.final != nil && (end > *s.rx.final || fin && end != *s.rx.final) {
			s.mu.Unlock()
			return protocolError(6, 8, "final size changed after stop")
		}
		s.rx.highest = max(s.rx.highest, end)
		if fin {
			if end < s.rx.highest {
				s.mu.Unlock()
				return protocolError(6, 8, "final size below received data")
			}
			v := end
			s.rx.final = &v
		}
	} else {
		if _, err = s.rx.insert(offset, data, fin); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	c.receiveTotal += newly
	s.notifyRead()
	s.mu.Unlock()
	if s.rxStopped {
		c.creditConsumed(s, s.rx.highest)
	}
	c.retire(s)
	return nil
}
func (c *Conn) resetStream(id, code, final uint64) error {
	s, err := c.peerStream(id, true)
	if err != nil || s == nil {
		return err
	}
	s.mu.Lock()
	if final > s.receiveLimit || final < s.rx.highest || s.rx.final != nil && *s.rx.final != final {
		s.mu.Unlock()
		return protocolError(6, 4, "RESET_STREAM final size")
	}
	extra := final - s.rx.highest
	if extra > c.receiveLimit-c.receiveTotal {
		s.mu.Unlock()
		return protocolError(3, 4, "RESET_STREAM flow limit")
	}
	c.receiveTotal += extra
	s.rx.highest = final
	s.rx.final = &final
	s.rxStopped = true
	s.ready = nil
	s.rx.parts = nil
	s.rx.buffered = 0
	// STOP_SENDINGへのRESET応答で、進行中のHTTP応答を取り消さない。
	if !s.readStopped {
		s.cancel()
	}
	s.readErr = &StreamError{Code: code, Remote: true}
	s.notifyRead()
	s.mu.Unlock()
	if s.rxStopped {
		c.creditConsumed(s, s.rx.highest)
	}
	c.retire(s)
	return nil
}
