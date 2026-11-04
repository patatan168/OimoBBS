// 受信鍵の世代を確認応答と結び、期限切れの古い鍵への参照を解放する。
package quicv1

import "time"

// expireReadKeys は再送のbackoffによらない保持期限で、旧受信鍵を到達不能にする。
func (c *Conn) expireReadKeys(now time.Time) {
	if c.previousRead != nil && !now.Before(c.previousReadUntil) {
		c.previousRead = nil
		c.previousReadUntil = time.Time{}
	}
}

// sentPhaseACK は現在の受信phaseを含むACKの送信queue投入後にだけ、次の更新を許可する。
// ACKは接続actorが生成し、当該phase以降の最大受信packet番号を必ず含める。
func (c *Conn) sentPhaseACK(space int, ack []byte) {
	if space == spaceApplication && len(ack) != 0 {
		c.readPhaseAcknowledged = true
	}
}
