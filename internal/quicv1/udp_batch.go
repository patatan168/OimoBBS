// 大きさの異なるUDP/GSO群も同じsendmmsgへ渡し、datagram境界を保って送信する。
package quicv1

import (
	"errors"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type udpBatch struct {
	messages [32]ipv4.Message
	ends     [32]int
	single   [32][]byte
	controls [32][]byte
	segment  int
	gso      []byte
}

// sendBatchOwned は連続暗号文をGSOへ渡し、端数やACKも同じOS呼出しへまとめる。
// 部分送信後の失敗では未送信分だけを再構成し、GSO非対応なら通常datagramへ戻す。
func (l *Listener) sendBatchOwned(packets [][]byte, owners []*packetBuffer, peer, local *net.UDPAddr) error {
	var batch udpBatch
	return l.sendBatchWith(packets, owners, peer, local, &batch, nil)
}

// sendBatchWith はsender専有の作業領域を再利用する。writerの差替えは部分送信の検証用。
func (l *Listener) sendBatchWith(packets [][]byte, owners []*packetBuffer, peer, local *net.UDPAddr, batch *udpBatch, writer udpBatchWriter) error {
	if len(packets) == 1 {
		return l.send(packets[0], peer, local)
	}
	if writer == nil {
		writer = l.packetConn
		if l.packetConn == nil {
			writer = ipv4.NewPacketConn(l.socket)
		}
	}
	defer func() {
		clear(batch.messages[:])
		clear(batch.single[:])
	}()
	var oob []byte
	if local.IP.To4() != nil {
		oob = (&ipv4.ControlMessage{Src: local.IP}).Marshal()
	} else {
		oob = (&ipv6.ControlMessage{Src: local.IP}).Marshal()
	}
	for len(packets) > 0 {
		messages, ends, hasGSO := l.udpMessages(packets, owners, peer, oob, batch)
		for len(messages) > 0 {
			l.sendCalls.Add(1)
			n, err := writer.WriteBatch(messages, 0)
			if n > 0 {
				consumed := ends[n-1]
				packets = packets[consumed:]
				if owners != nil {
					owners = owners[consumed:]
				}
				messages, ends = messages[n:], ends[n:]
				for i := range ends {
					ends[i] -= consumed
				}
			}
			if err != nil {
				if hasGSO && !l.gsoDisabled.Swap(true) {
					break
				}
				return err
			}
			if n == 0 {
				return errors.New("empty UDP batch write")
			}
		}
	}
	return nil
}

type udpBatchWriter interface {
	WriteBatch([]ipv4.Message, int) (int, error)
}

// udpMessages は各OS messageの末尾datagram位置も返し、部分送信で重複しないようにする。
func (l *Listener) udpMessages(packets [][]byte, owners []*packetBuffer, peer *net.UDPAddr, oob []byte, batch *udpBatch) ([]ipv4.Message, []int, bool) {
	messages := batch.messages[:0]
	ends := batch.ends[:0]
	hasGSO := false
	for start := 0; start < len(packets) && len(messages) < len(batch.messages); {
		segment := len(packets[start])
		end := start + 1
		if segment > 1100 && !l.gsoDisabled.Load() {
			for end < len(packets) && len(packets[end]) <= segment {
				end++
				if len(packets[end-1]) < segment {
					break
				}
			}
		}
		control := oob
		iov := packets[start : start+1]
		if end > start+1 {
			if batch.segment != segment {
				batch.segment, batch.gso = segment, gsoControl(segment)
			}
			if len(batch.gso) > 0 {
				slot := len(messages)
				control = append(batch.controls[slot][:0], oob...)
				control = append(control, batch.gso...)
				batch.controls[slot] = control
				iov = packets[start:end]
				if len(owners) >= end {
					if contiguous := contiguousCiphertext(owners[start:end], end-start); contiguous != nil {
						batch.single[slot] = contiguous
						iov = batch.single[slot : slot+1]
					}
				}
				hasGSO = true
			} else {
				end = start + 1
			}
		}
		messages = append(messages, ipv4.Message{Buffers: iov, OOB: control, Addr: peer})
		ends = append(ends, end)
		start = end
	}
	return messages, ends, hasGSO
}
