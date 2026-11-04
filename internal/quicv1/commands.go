// stream I/Oの要求を接続actorで確定し、peer creditと有限queueを同時に守る。
package quicv1

import (
	"errors"
	"io"
	"os"
	"time"
)

func (c *Conn) handleCommand(command any) error {
	switch value := command.(type) {
	case drainRequest:
		if len(c.drainers) < 32 {
			c.drainers = append(c.drainers, value.done)
		}
		c.notifyDrained()
	case *writeRequest:
		if len(c.blocked) >= 64 {
			value.block.release()
			err := errors.New("QUIC write queue exhausted")
			value.complete(err)
			if value.asynchronous {
				value.stream.mu.Lock()
				value.stream.writeErr = err
				value.stream.notifyWrite()
				value.stream.mu.Unlock()
				c.resetWrite(value.stream, 0x10c)
			}
			return nil
		}
		c.blocked = append(c.blocked, value)
		c.processBlocked()
	case streamCommand:
		s := c.streams[value.id]
		switch value.kind {
		case commandOpenUni:
			if c.localNextUni >= c.peerMaxUni {
				value.done <- errors.New("peer unidirectional stream credit exhausted")
				break
			}
			id := c.localNextUni*4 + 3
			c.localNextUni++
			s = newStream(c, id)
			s.txLimit = c.peerUni
			s.rxStopped = true
			s.rx.final = new(uint64)
			s.readErr = io.EOF
			c.streams[id] = s
			value.opened <- s
		case commandClose:
			frame := appendVarint(nil, 0x1d)
			frame = appendVarint(frame, value.code)
			frame = append(frame, 0)
			if err := c.transmit(spaceApplication, frame, nil, time.Now(), true); err == nil {
				_ = c.listener.waitSend(c)
			}
			return errClosed
		case commandFIN:
			if s != nil && !s.resetSent {
				for i := len(c.blocked) - 1; i >= 0; i-- {
					if pending := c.blocked[i]; pending.stream == s {
						pending.final = true
						return nil
					}
				}
				frame := appendVarint(nil, 0x0f)
				frame = appendVarint(frame, s.id)
				frame = appendVarint(frame, s.txOffset)
				frame = append(frame, 0)
				c.queue(spaceApplication, frame)
			}
		case commandReset:
			if s != nil {
				c.resetWrite(s, value.code)
			}
		case commandReadDone:
			if s != nil {
				s.rxStopped = true
				c.creditConsumed(s, s.rx.highest)
				c.retire(s)
			}
		case commandStop:
			if s == nil {
				break
			}
			s.rxStopped = true
			c.creditConsumed(s, s.rx.highest)
			frame := appendVarint(nil, 5)
			frame = appendVarint(frame, s.id)
			frame = appendVarint(frame, value.code)
			c.queue(spaceApplication, frame)
			c.retire(s)
		case commandConsume:
			if s != nil {
				c.creditConsumed(s, value.value)
			}

		}
	}
	return nil
}
func (c *Conn) resetWrite(s *Stream, code uint64) {
	if s.resetSent {
		return
	}
	s.resetSent = true
	frame := appendVarint(nil, 4)
	frame = appendVarint(frame, s.id)
	frame = appendVarint(frame, code)
	frame = appendVarint(frame, s.txOffset)
	c.queue(spaceApplication, frame)
}
func (c *Conn) processBlocked() {
	if !c.handshakeDone {
		return
	}
	remaining := c.blocked[:0]
	c.nextWriteExpiry = time.Time{}
	for _, request := range c.blocked {
		if request.cancelled.Load() || request.context != nil && request.context.Err() != nil {
			err := errors.New("QUIC write cancelled")
			if request.context != nil && request.context.Err() != nil {
				err = request.context.Err()
			}
			request.block.release()
			request.complete(err)
			continue
		}
		s := request.stream
		s.mu.Lock()
		err, deadline := s.writeErr, s.writeDeadline
		// リース失効による期限変更をactorでも確認する。待機goroutineの起床前に
		// peer creditが増えても、失効済みの残り本文を受理しない。
		if err == nil && !deadline.IsZero() && !time.Now().Before(deadline) {
			err = os.ErrDeadlineExceeded
			s.writeErr = err
			s.notifyWrite()
		}
		s.mu.Unlock()
		request.deadline = deadline
		if errors.Is(err, os.ErrDeadlineExceeded) {
			c.resetWrite(s, 0x10c)
		}
		if err != nil || s.resetSent {
			if err == nil {
				err = io.ErrClosedPipe
			}
			request.block.release()
			request.complete(err)
			continue
		}
		available := min(c.peerMaxData-min(c.txTotal, c.peerMaxData), s.txLimit-min(s.txOffset, s.txLimit))
		if c.queuedBytes > 256<<10 || available == 0 {
			remaining = append(remaining, request)
			if request.asynchronous && !request.deadline.IsZero() && (c.nextWriteExpiry.IsZero() || request.deadline.Before(c.nextWriteExpiry)) {
				c.nextWriteExpiry = request.deadline
			}
			continue
		}
		accepted := min(request.size-request.offset, int(min(available, 65<<10)))
		for accepted > 0 {
			n := min(accepted, request.chunk-request.offset%request.chunk)
			fin := request.final && request.offset+n == request.size
			request.block.refs++
			c.queueRefs(spaceApplication, request.frameData(s.id, s.txOffset, n, fin), request.block.single)
			s.txOffset += uint64(n)
			c.txTotal += uint64(n)
			request.offset += n
			accepted -= n
		}
		if request.offset == request.size {
			request.block.release()
			request.complete(nil)
		} else {
			remaining = append(remaining, request)
			if request.asynchronous && !request.deadline.IsZero() && (c.nextWriteExpiry.IsZero() || request.deadline.Before(c.nextWriteExpiry)) {
				c.nextWriteExpiry = request.deadline
			}
		}
	}
	c.blocked = remaining
	c.scheduleMTU()
}
func (c *Conn) retire(s *Stream) {
	s.mu.Lock()
	done := s.txFinalAcked && s.rxStopped && s.rx.final != nil
	if done {
		s.stopWriteTimer()
	}
	s.mu.Unlock()
	if !done {
		return
	}
	// 完了済みstreamを親接続のcontext childrenへ残さない。
	s.cancel()
	if s.id&1 != 0 {
		return
	} // 接続寿命を共有するserver制御streamは接続終了時に回収する。
	delete(c.streams, s.id)
	kind := int((s.id >> 1) & 1)
	ordinal := s.id / 4
	c.finished[kind][ordinal] = true
	for c.finished[kind][c.retired[kind]] {
		delete(c.finished[kind], c.retired[kind])
		c.retired[kind]++
	}
	limit := uint64(32)
	step := uint64(16)
	frameType := uint64(0x12)
	if kind == 1 {
		limit = 3
		step = 1
		frameType = 0x13
	}
	if c.retired[kind]+limit >= c.localCredit[kind]+step {
		c.localCredit[kind] = c.retired[kind] + limit
		frame := appendVarint(nil, frameType)
		frame = appendVarint(frame, c.localCredit[kind])
		c.queue(spaceApplication, frame)
	}
}

// ackedFrames はFIN/RESETの送達を確認してからstreamの並行枠を返す。
func (c *Conn) ackedFrames(data []byte) {
	r := wireReader{data: data}
	for r.left() > 0 {
		kind, err := r.integer()
		if err != nil {
			return
		}
		switch {
		case kind >= 8 && kind <= 15:
			id, err := r.integer()
			if err != nil {
				return
			}
			if kind&4 != 0 {
				if _, err = r.integer(); err != nil {
					return
				}
			}
			if kind&2 != 0 {
				if _, err = r.blob(); err != nil {
					return
				}
			} else {
				_, _ = r.take(r.left())
			}
			if kind&1 != 0 {
				if s := c.streams[id]; s != nil {
					s.mu.Lock()
					s.txFinalAcked = true
					s.mu.Unlock()
					c.retire(s)
				}
			}
		case kind == 4:
			id, err := r.integer()
			if err != nil {
				return
			}
			if _, err = r.integer(); err != nil {
				return
			}
			if _, err = r.integer(); err != nil {
				return
			}
			if s := c.streams[id]; s != nil {
				s.mu.Lock()
				s.txFinalAcked = true
				s.mu.Unlock()
				c.retire(s)
			}
		case kind == 6:
			if _, err = r.integer(); err != nil {
				return
			}
			if _, err = r.blob(); err != nil {
				return
			}
		case kind == 5 || kind == 0x11:
			if _, err = r.integer(); err != nil {
				return
			}
			if _, err = r.integer(); err != nil {
				return
			}
		case kind == 0x10 || kind == 0x12 || kind == 0x13 || kind == 0x19:
			if _, err = r.integer(); err != nil {
				return
			}
		case kind == 0x1b:
			if _, err = r.take(8); err != nil {
				return
			}
		case kind == 0 || kind == 1 || kind == 0x1e:
		default:
			return
		}
	}
}

// creditConsumed は読取りと破棄の両方で接続creditを返す。停止streamの受信窓は広げない。
func (c *Conn) creditConsumed(s *Stream, consumed uint64) {
	if consumed <= s.consumedReported {
		return
	}
	c.receiveConsumed += consumed - s.consumedReported
	s.consumedReported = consumed
	s.mu.Lock()
	if !s.rxStopped && consumed+(64<<10) >= s.receiveLimit+(32<<10) {
		s.receiveLimit = consumed + (64 << 10)
		f := appendVarint(nil, 0x11)
		f = appendVarint(f, s.id)
		f = appendVarint(f, s.receiveLimit)
		c.queue(spaceApplication, f)
	}
	s.mu.Unlock()
	if c.receiveConsumed+(256<<10) >= c.receiveLimit+(128<<10) {
		c.receiveLimit = c.receiveConsumed + (256 << 10)
		f := appendVarint(nil, 0x10)
		f = appendVarint(f, c.receiveLimit)
		c.queue(spaceApplication, f)
	}
}
