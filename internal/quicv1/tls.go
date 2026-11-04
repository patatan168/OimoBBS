// TLSイベントをQUICの暗号化level・CRYPTO offset・transport parameterへ接続する。
package quicv1

import (
	"bytes"
	"crypto/tls"
	"time"
)

func (c *Conn) parameters() []byte {
	var out []byte
	blob := func(id uint64, value []byte) {
		out = appendVarint(out, id)
		out = appendVarint(out, uint64(len(value)))
		out = append(out, value...)
	}
	integer := func(id, value uint64) { blob(id, appendVarint(nil, value)) }
	blob(0, c.originalID)
	integer(1, 30000)
	integer(3, 1200)
	integer(4, 256<<10)
	integer(5, 64<<10)
	integer(6, 64<<10)
	integer(7, 64<<10)
	integer(8, 32)
	integer(9, 3)
	blob(12, nil)
	integer(14, 2)
	blob(15, c.id)
	blob(16, c.id)
	return out
}
func (c *Conn) peerParameters(data []byte) error {
	if len(data) > 4096 {
		return protocolError(8, 6, "transport parameters exceed budget")
	}
	seen := make(map[uint64]bool)
	r := wireReader{data: data}
	initialID := false
	for r.left() > 0 {
		id, err := r.integer()
		if err != nil {
			return err
		}
		value, err := r.blob()
		if err != nil {
			return err
		}
		if seen[id] {
			return protocolError(8, 6, "duplicate transport parameter")
		}
		seen[id] = true
		switch id {
		case 0, 2, 13, 16:
			return protocolError(8, 6, "server-only transport parameter")
		case 15:
			if !bytes.Equal(value, c.peerID) {
				return protocolError(8, 6, "initial source CID mismatch")
			}
			initialID = true
			continue
		case 12:
			if len(value) != 0 {
				return protocolError(8, 6, "migration flag must be empty")
			}
			continue
		}
		switch id {
		case 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14:
			v := wireReader{data: value}
			number, err := v.integer()
			if err != nil || v.left() != 0 {
				return protocolError(8, 6, "invalid integer parameter")
			}
			switch id {
			case 1:
				if number > 0 {
					c.idleTimeout = time.Duration(min(number, 30000)) * time.Millisecond
				}
			case 3:
				c.peerMaxUDP = int(min(number, 1452))
				if number < 1200 {
					return protocolError(8, 6, "UDP payload below minimum")
				}
			case 4:
				c.peerMaxData = number
			case 5:
				c.peerBidiLocal = number
			case 6:
				c.peerBidiRemote = number
			case 7:
				c.peerUni = number
			case 8, 9:
				if number > 1<<60 {
					return protocolError(8, 6, "stream limit overflow")
				}
				if id == 9 {
					c.peerMaxUni = number
				}
			case 10:
				if number > 20 {
					return protocolError(8, 6, "ACK exponent exceeds maximum")
				}
				c.recovery.peerAckExponent = number
			case 11:
				if number >= 1<<14 {
					return protocolError(8, 6, "ACK delay exceeds maximum")
				}
				c.recovery.peerMaxAckDelay = time.Duration(number) * time.Millisecond
			case 14:
				if number < 2 {
					return protocolError(8, 6, "CID limit below minimum")
				}
			}
		}
	}
	if !initialID {
		return protocolError(8, 6, "initial source CID missing")
	}
	c.parametersReceived = true
	return nil
}
func tlsSpace(level tls.QUICEncryptionLevel) int {
	switch level {
	case tls.QUICEncryptionLevelInitial:
		return spaceInitial
	case tls.QUICEncryptionLevelHandshake:
		return spaceHandshake
	default:
		return spaceApplication
	}
}
func (c *Conn) drainTLS() error {
	for {
		event := c.tls.NextEvent()
		switch event.Kind {
		case tls.QUICNoEvent:
			return nil
		case tls.QUICSetReadSecret, tls.QUICSetWriteSecret:
			if event.Level == tls.QUICEncryptionLevelEarly {
				return protocolError(0xa, 6, "0-RTT is disabled")
			}
			key, err := trafficKeys(event.Data, event.Suite)
			if err != nil {
				return err
			}
			space := &c.spaces[tlsSpace(event.Level)]
			if event.Kind == tls.QUICSetReadSecret {
				space.read = key
			} else {
				space.write = key
			}
		case tls.QUICWriteData:
			index := tlsSpace(event.Level)
			s := &c.spaces[index]
			data := event.Data
			for len(data) > 0 {
				n := min(len(data), 900)
				frame := appendVarint(nil, 6)
				frame = appendVarint(frame, s.cryptoTX)
				frame = appendVarint(frame, uint64(n))
				frame = append(frame, data[:n]...)
				c.queue(index, frame)
				s.cryptoTX += uint64(n)
				data = data[n:]
			}
		case tls.QUICTransportParameters:
			if err := c.peerParameters(event.Data); err != nil {
				return err
			}
		case tls.QUICTransportParametersRequired:
			c.tls.SetTransportParameters(c.parameters())
		case tls.QUICHandshakeDone:
			if !c.parametersReceived {
				return protocolError(8, 6, "peer parameters missing")
			}
			c.stateMu.Lock()
			c.tlsState = c.tls.ConnectionState()
			c.stateMu.Unlock()
			c.handshakeDone = true
			c.scheduleMTU()
			c.queue(spaceApplication, []byte{0x1e})
			if !c.accepted {
				c.accepted = true
				select {
				case c.listener.accepted <- c:
				default:
					return protocolError(2, 0, "listener admission exhausted")
				}
			}
		case tls.QUICResumeSession:
			event.SessionState.EarlyData = false
		case tls.QUICStoreSession: // サーバーの再開ticketを保存しない。
		case tls.QUICRejectedEarlyData:
		case tls.QUICErrorEvent:
			if event.Err != nil {
				return event.Err
			}
		}
	}
}
func (c *Conn) cryptoFrame(index int, offset uint64, data []byte) error {
	s := &c.spaces[index]
	if _, err := s.cryptoRX.insert(offset, data, false); err != nil {
		return err
	}
	level := tls.QUICEncryptionLevelInitial
	if index == spaceHandshake {
		level = tls.QUICEncryptionLevelHandshake
	}
	if index == spaceApplication {
		level = tls.QUICEncryptionLevelApplication
	}
	for {
		block := s.cryptoRX.pop()
		if block == nil {
			break
		}
		if err := c.tls.HandleData(level, block); err != nil {
			return err
		}
		if err := c.drainTLS(); err != nil {
			return err
		}
	}
	return nil
}
