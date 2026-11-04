// 経路検証の応答は最小datagram長と輻輳制御を守り、損失時も同じ応答を再送しない。
package quicv1

import "time"

// allowPathResponse は小さい入力から1200byte応答を繰り返させる処理を接続ごとに制限する。
// 最大8件のburstと毎秒1件の補充だけを許可し、peerが通信しても枠を増やさない。
func (c *Conn) allowPathResponse(now time.Time) bool {
	if c.pathResponseAt.IsZero() {
		c.pathResponseAt = now
		c.pathResponseCredit = 8
	}
	if elapsed := now.Sub(c.pathResponseAt) / time.Second; elapsed > 0 {
		c.pathResponseCredit = min(8, c.pathResponseCredit+int(min(elapsed, 8)))
		c.pathResponseAt = c.pathResponseAt.Add(elapsed * time.Second)
	}
	if c.pathResponseCredit == 0 {
		return false
	}
	c.pathResponseCredit--
	return true
}

// transmitOnce はPATH_RESPONSEを1200byte以上にpadし、ACK待ちのbyte数だけを保持する。
// frame本体は履歴へ残さず、PTOでは新しいPINGでACKを促す。
func (c *Conn) transmitOnce(space int, payload, frames []byte, now time.Time, refs []*sendBlock) error {
	s := &c.spaces[space]
	pn := s.next
	pnSize := 2
	if pn-s.largestAcked >= 1<<15 {
		pnSize = 4
	}
	target := 1200 - (1 + len(c.peerID) + pnSize + 16)
	if len(payload) < target {
		copy(c.padding[:], payload)
		clear(c.padding[len(payload):target])
		payload = c.padding[:target]
	}
	if err := c.transmit(space, payload, frames, now, false, refs); err != nil {
		return err
	}
	packet := s.sent[pn]
	packet.frames = nil
	packet.retransmittable = false
	s.sent[pn] = packet
	return nil
}
