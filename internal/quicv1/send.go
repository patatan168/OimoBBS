// 有限の送信queueをNewReno/PTOとACKに接続し、損失時はframeを新しいpacket番号で再送する。
package quicv1

import (
	"sync"
	"time"
)

type packetBuffer struct {
	data    []byte
	initial *initialPacket
	owner   *cipherBlock
	offset  int
}

var sendBuffers = sync.Pool{New: func() any { return &packetBuffer{data: make([]byte, 0, 1200)} }}

func (c *Conn) flush(now time.Time) (err error) {
	c.batching = true
	var acks [3][]byte
	defer func() {
		if e := c.sendBatch(); err == nil {
			err = e
		}
		c.batching = false
	}()
	for len(c.pending) > 0 && c.recovery.inFlight+datagramSize <= min(c.recovery.cwnd, 1<<20) {
		if now.Add(c.paceQuantum()).Before(c.nextPace) {
			break
		}
		item := c.pending[0]
		s := &c.spaces[item.space]
		if s.write == nil {
			break
		}
		budget := c.mtu - (1 + len(c.peerID) + 4 + 16)
		if item.space != spaceApplication {
			budget = 1100
		}
		if acks[item.space] == nil {
			acks[item.space] = s.ackFrame(now)
		}
		ack := acks[item.space]
		if len(ack)+len(item.data) > budget {
			// 満杯の本文に入らないACKは同じflushの端数へ回す。
			// 残ったACKは下のloopで必ず送り、次のtimerまで持ち越さない。
			ack = nil
		}
		budget -= len(ack)
		var frames []byte
		var refs []*sendBlock
		count := 0
		for _, next := range c.pending {
			if next.space != item.space || next.unreliable != item.unreliable || len(frames)+len(next.data) > budget {
				break
			}
			if count == 0 {
				frames = next.data
				refs = next.refs
			} else {
				frames = append(frames, next.data...)
				if len(next.refs) > 0 {
					combined := make([]*sendBlock, 0, len(refs)+len(next.refs))
					combined = append(combined, refs...)
					refs = append(combined, next.refs...)
				}
			}
			count++
		}
		if count == 0 && len(item.data) > budget {
			parts, e := splitFrames(item.data, c.mtu-65)
			if e != nil {
				return e
			}
			for i := range parts {
				parts[i] = append([]byte(nil), parts[i]...)
			}
			releaseRefs(item.refs)
			c.consumePending(1)
			c.queuedBytes -= len(item.data)
			entries := make([]queuedFrame, 0, len(parts)+len(c.pending))
			for _, part := range parts {
				entries = append(entries, queuedFrame{space: item.space, data: part, unreliable: item.unreliable})
				c.queuedBytes += len(part)
			}
			entries = append(entries, c.pending...)
			c.pending = entries
			c.pendingBase = entries[:cap(entries)]
			continue
		}
		if count == 0 {
			return protocolError(1, 0, "internal frame exceeds packet budget")
		}
		if len(ack) > 0 {
			acks[item.space] = nil
		}
		c.consumePending(count)
		c.queuedBytes -= len(frames)
		payload := frames
		if len(ack) > 0 {
			payload = make([]byte, 0, len(frames)+len(ack))
			payload = append(payload, frames...)
			payload = append(payload, ack...)
		}
		var sendErr error
		if item.unreliable {
			sendErr = c.transmitOnce(item.space, payload, frames, now, refs)
		} else {
			sendErr = c.transmit(item.space, payload, frames, now, false, refs)
		}
		if sendErr != nil {
			return sendErr
		}
		c.sentPhaseACK(item.space, ack)
		interval := time.Duration(int64(datagramSize) * int64(c.recovery.smoothed) / int64(max(c.recovery.cwnd, 1)))
		// 初期handshake後は最大10 packet・1ms相当までをまとめ、timer粒度による停止を避ける。
		if c.handshakeDone {
			c.nextPace = maxTime(c.nextPace, now).Add(interval)
		}
		now = time.Now()
	}
	for index := range c.spaces {
		s := &c.spaces[index]
		ack := acks[index]
		if len(ack) == 0 && s.ackPending && !now.Before(s.ackAt) && s.write != nil {
			ack = s.ackFrame(now)
		}
		if len(ack) > 0 {
			if err := c.transmit(index, ack, nil, now, true); err != nil {
				return err
			}
			c.sentPhaseACK(index, ack)
		}
	}
	return nil
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
func (c *Conn) transmit(index int, payload, reliable []byte, now time.Time, probe bool, owned ...[]*sendBlock) error {
	var refs []*sendBlock
	if len(owned) > 0 {
		refs = owned[0]
	}
	retained := false
	defer func() {
		if !retained {
			releaseRefs(refs)
		}
	}()
	select {
	case <-c.ctx.Done():
		return errClosed
	default:
	}
	s := &c.spaces[index]
	if s.write == nil {
		return nil
	}
	if s.next >= maxVarint {
		c.cancel()
		return protocolError(0xe, 0, "packet number exhausted")
	}
	if len(reliable) > 0 && len(s.sent) >= 1024 {
		return protocolError(1, 0, "sent packet history budget")
	}
	if index == spaceApplication {
		if c.handshakeDone && c.writePhaseAcked && c.keyPhase == c.readKeyPhase && c.writeKeyPackets >= c.listener.cfg.KeyUpdateAfter {
			next, err := s.write.next()
			if err != nil {
				return err
			}
			s.write = next
			c.keyPhase = !c.keyPhase
			c.writeKeyPackets = 0
			c.writePhaseFirst = s.next
			c.writePhaseAcked = false
			c.queue(spaceApplication, []byte{1})
		}
		if c.writeKeyPackets >= 1<<20 {
			return protocolError(0xf, 0, "packet key usage limit")
		}
		c.writeKeyPackets++
	}
	// 暗号化を試みた番号は送信失敗でも戻さず、同じ鍵とnonceの再利用を防ぐ。
	pn := s.next
	s.next++
	pnSize := 2
	if pn-s.largestAcked >= 1<<15 {
		pnSize = 4
	}
	paddingTarget := c.mtu - (1 + len(c.peerID) + pnSize + 16)
	if c.batching && index == spaceApplication && len(payload) > c.mtu-80 && (len(c.batch) > 0 || len(c.pending) > 0) && len(payload) < paddingTarget {
		copy(c.padding[:], payload)
		clear(c.padding[len(payload):paddingTarget])
		payload = c.padding[:paddingTarget]
	}
	for len(payload) < 4-pnSize {
		payload = append(payload, 0)
	}
	header, offset := appendPacketHeader(c.headerBuffer[:0], index, c.peerID, c.id, pn, len(payload), c.keyPhase, pnSize)
	if index == spaceInitial && !c.batching && len(reliable) > 0 && len(header)+len(payload)+16 < 1200 {
		size := 1200 - len(header) - 16
		copy(c.padding[:], payload)
		clear(c.padding[len(payload):size])
		payload = c.padding[:size]
		header, offset = appendPacketHeader(c.headerBuffer[:0], index, c.peerID, c.id, pn, len(payload), c.keyPhase, pnSize)
	}
	buffer := c.packetStorage(index, len(header)+len(payload)+16)
	var packet []byte
	var err error
	buffer.initial = nil
	if index == spaceInitial && c.batching && len(reliable) > 0 {
		size := len(header) + len(payload) + 16
		if cap(buffer.data) < size {
			buffer.data = make([]byte, size)
		}
		packet = buffer.data[:size]
		buffer.initial = &initialPacket{key: s.write, number: pn, payload: append([]byte(nil), payload...), pnSize: pnSize}
	} else {
		packet, err = s.write.sealPacketInto(buffer.data[:0], header, payload, pn, offset)
	}
	if err != nil {
		releasePacket(buffer)
		return err
	}
	buffer.data = packet
	c.listener.sentPackets.Add(1)

	if c.batching {
		c.batch = append(c.batch, buffer)
		if len(c.batch) >= 32 {
			if err = c.sendBatch(); err != nil {
				return err
			}
		}
	} else {
		if err = c.listener.enqueueSend([]*packetBuffer{buffer}, c); err != nil {
			return err
		}
	}

	if len(reliable) > 0 {
		s.sent[pn] = sentPacket{number: pn, at: now, size: len(packet), frames: reliable, retransmittable: true, refs: refs}
		s.sentOrder = append(s.sentOrder, pn)
		retained = true
		c.recovery.inFlight += len(packet)
		c.recovery.lastSent = now
	}
	return nil
}
func (c *Conn) detectLost(index int, now time.Time) {
	s := &c.spaces[index]
	if !s.hasAcked {
		return
	}
	threshold := max(time.Millisecond, 9*max(c.recovery.latest, c.recovery.smoothed)/8)
	for _, number := range s.sentOrder[s.sentHead:] {
		if number > s.largestAcked {
			break
		}
		packet, ok := s.sent[number]
		if !ok {
			continue
		}
		packetThreshold := number <= s.largestAcked && s.largestAcked-number >= 3
		timeThreshold := number < s.largestAcked && now.Sub(packet.at) >= threshold
		if !packetThreshold && !timeThreshold {
			continue
		}
		delete(s.sent, number)
		if packet.mtuProbe > 0 {
			c.recovery.inFlight = max(0, c.recovery.inFlight-packet.size)
			c.lostMTU(now)
			continue
		}
		if packet.size > 1200 {
			if c.largeLosses == 0 {
				c.firstLargeLoss = now
			}
			c.largeLosses++
			// 大きいpacketの直近ACKがある間は輻輳損失として扱い、小さいpacketだけが届く状態を確認する。
			delay := c.recovery.basePTO()
			if c.largeLosses >= 3 && c.mtu > 1200 && now.Sub(c.lastLargeAck) >= delay && now.Sub(c.firstLargeLoss) >= delay && c.lastSmallAck.After(c.firstLargeLoss) {
				c.shrinkMTU()
			}
		}
		c.recovery.lost(packet, now)
		c.listener.lostPackets.Add(1)
		if packet.retransmittable {
			c.queueRefs(index, packet.frames, packet.refs)
		} else {
			releaseRefs(packet.refs)
		}
	}
	s.pruneSent()
}
func (c *Conn) nextWake(now time.Time) time.Duration {
	next := minTime(now.Add(time.Second), c.lastActivity.Add(max(c.idleTimeout, 3*c.recovery.basePTO())))
	if c.previousRead != nil && c.previousReadUntil.Before(next) {
		next = c.previousReadUntil
	}
	if !c.nextWriteExpiry.IsZero() && c.nextWriteExpiry.Before(next) {
		next = c.nextWriteExpiry
	}
	if !c.mtuProbePending && c.mtuFailures < 3 && !c.mtuProbeAt.IsZero() && c.mtuProbeAt.Before(next) {
		next = c.mtuProbeAt
	}
	for i := range c.spaces {
		s := &c.spaces[i]
		if s.ackPending && s.write != nil && s.ackAt.Before(next) {
			next = s.ackAt
		}
	}
	if c.recovery.inFlight > 0 {
		pto := c.recovery.lastSent.Add(c.recovery.pto())
		if pto.Before(next) {
			next = pto
		}
	}
	if len(c.pending) > 0 && c.recovery.inFlight+datagramSize <= min(c.recovery.cwnd, 1<<20) && c.nextPace.Add(-c.paceQuantum()).Before(next) {
		next = c.nextPace.Add(-c.paceQuantum())
	}
	return max(time.Microsecond, time.Until(next))
}
func (c *Conn) onTimer(now time.Time) {
	c.expireReadKeys(now)
	c.processBlocked()
	c.maybeProbeMTU(now)
	for i := range c.spaces {
		c.detectLost(i, now)
	}
	if c.recovery.inFlight == 0 || now.Before(c.recovery.lastSent.Add(c.recovery.pto())) {
		return
	}
	index := -1
	var oldest sentPacket
	for i := range c.spaces {
		s := &c.spaces[i]
		if s.write == nil {
			continue
		}
		s.pruneSent()
		if s.sentHead < len(s.sentOrder) {
			packet := s.sent[s.sentOrder[s.sentHead]]
			if index < 0 || packet.at.Before(oldest.at) {
				index = i
				oldest = packet
			}
		}
	}
	if index < 0 {
		return
	}
	if c.recovery.ptoCount >= 2 && c.mtu > 1200 {
		c.shrinkMTU()
	}
	// PTO probeはcwnd満杯でも一つ送り、元packetを消さずACKによる送達確認を保つ。
	frames := oldest.frames
	refs := oldest.refs
	if !oldest.retransmittable || len(frames) == 0 || len(frames) > c.mtu-65 {
		frames = []byte{1}
		refs = nil
	}
	ack := c.spaces[index].ackFrame(now)
	payload := append([]byte(nil), frames...)
	payload = append(payload, ack...)
	retainRefs(refs)
	if err := c.transmit(index, payload, frames, now, true, refs); err != nil {
		c.cancel()
	} else {
		c.sentPhaseACK(index, ack)
	}
	c.recovery.ptoCount++
}

// paceQuantum は一度に送るburstを初期cwnd以下に収める。
func (c *Conn) paceQuantum() time.Duration {
	interval := time.Duration(int64(datagramSize) * int64(c.recovery.smoothed) / int64(max(1, c.recovery.cwnd)))
	return min(time.Millisecond, 10*interval)
}

// sendBatch は同じendpointの暗号化済みpacketをOSへまとめて渡す。
func (c *Conn) sendBatch() error {
	if c.cipherBatch != nil {
		block := c.cipherBatch
		c.cipherBatch = nil
		block.release()
	}
	if len(c.batch) == 0 {
		return nil
	}
	batch := c.batch
	c.batch = nil
	combined, err := c.coalesceInitial(batch)
	if err != nil {
		for _, b := range batch {
			releasePacket(b)
		}
		return err
	}
	return c.listener.enqueueSend(combined, c)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
