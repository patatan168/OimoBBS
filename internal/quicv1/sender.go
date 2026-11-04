// 暗号化済みUDPのI/Oを有限queueで分離し、接続actorがOS送信中も受信・ACKを処理できるようにする。
package quicv1

import "net"

type sendBurst struct {
	packets     []*packetBuffer
	peer, local *net.UDPAddr
	conn        *Conn
	done        chan error
}

// enqueueSend は暗号化済みbufferの所有権をsenderへ移す。失敗時は呼出元へ返さずpoolへ戻す。
func (l *Listener) enqueueSend(packets []*packetBuffer, c *Conn) error {
	burst := sendBurst{packets: packets, peer: c.peer, local: c.local, conn: c}
	select {
	case l.sendQueue <- burst:
		return nil
	case <-l.closed:
		for _, b := range packets {
			releasePacket(b)
		}
		return net.ErrClosed
	case <-c.ctx.Done():
		for _, b := range packets {
			releasePacket(b)
		}
		return c.ctx.Err()
	}
}
func (l *Listener) writeLoop() {
	defer l.sendWorkers.Done()
	// sendBatchが戻るまでは次のburstを処理しないため、syscall用sliceを再利用できる。
	var data [32][]byte
	var batch udpBatch
	send := func(burst sendBurst) {
		if len(burst.packets) == 0 {
			if burst.done != nil {
				burst.done <- nil
			}
			return
		}
		for i, b := range burst.packets {
			data[i] = b.data
		}
		err := l.sendBatchWith(data[:len(burst.packets)], burst.packets, burst.peer, burst.local, &batch, nil)
		for _, b := range burst.packets {
			releasePacket(b)
		}
		if err != nil {
			burst.conn.cancel()
		}
	}
	var pending *sendBurst
	for {
		var burst sendBurst
		if pending != nil {
			burst = *pending
			pending = nil
		} else {
			select {
			case burst = <-l.sendQueue:
			case <-l.sendDone:
				for {
					select {
					case burst = <-l.sendQueue:
						send(burst)
					default:
						return
					}
				}
			}
		}
		for burst.done == nil && len(burst.packets) < 32 {
			select {
			case next := <-l.sendQueue:
				if next.done == nil && next.conn == burst.conn && len(burst.packets)+len(next.packets) <= 32 {
					burst.packets = append(burst.packets, next.packets...)
				} else {
					pending = &next
				}
			default:
			}
			if pending != nil || len(l.sendQueue) == 0 {
				break
			}
		}
		send(burst)
	}

}

// waitSend はCONNECTION_CLOSEより前のUDP送信が完了するまで待つ。
func (l *Listener) waitSend(c *Conn) error {
	done := make(chan error, 1)
	select {
	case l.sendQueue <- sendBurst{conn: c, done: done}:
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-l.closed:
		return net.ErrClosed
	}
	select {
	case err := <-done:
		return err
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-l.closed:
		return net.ErrClosed
	}
}
