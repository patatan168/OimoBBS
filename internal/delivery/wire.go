// HTTP送信片に通信ヘッダ分を加え、回線予算に近い量を予約する。
package delivery

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// estimatedWireBytes は1200byteごとにIPv6/TCPオプション/Ethernet相当の
// 112byte、送信片ごとにTLS/HTTP framingの余裕64byteを加える。
// 対象は1..Chunk。再送、接続確立、制御frame、他プロセスの通信は含まない。
// 実packetへの分割を観測した値でも、NIC帯域の保証値でもない。
func estimatedWireBytes(size int) int {
	framed := size + 64
	return framed + (framed+1199)/1200*112
}

// reserveHTTP はHTTP本文/推定ヘッダに通信分を加えた一つの枠を予約する。
// 待機・取消・IP別公平性は通常の予約と共有し、250msの期限を入口から数える。
func (s *Scheduler) reserveHTTP(ctx context.Context, ip netip.Addr, size int) (*Permit, error) {
	if size < 1 || size > Chunk {
		return nil, errors.New("invalid HTTP delivery reservation")
	}
	return s.reserveUntil(ctx, ip, estimatedWireBytes(size), estimatedWireBytes(Chunk), schedulerNow().Add(250*time.Millisecond))
}
