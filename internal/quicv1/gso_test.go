// UDP一括送信の実datagram境界と、GSO無効時の代替経路を検査する。
package quicv1

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestBatchedDatagramBoundaries(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		for _, fallback := range []bool{false, true} {
			t.Run(ip+map[bool]string{false: "/gso", true: "/fallback"}[fallback], func(t *testing.T) {
				receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
				if err != nil {
					t.Skip(err)
				}
				defer receiver.Close()
				sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
				if err != nil {
					t.Fatal(err)
				}
				defer sender.Close()
				l := &Listener{socket: sender}
				l.gsoDisabled.Store(fallback)
				packets := [][]byte{bytes.Repeat([]byte{1}, 1184), bytes.Repeat([]byte{2}, 1184), bytes.Repeat([]byte{3}, 300), bytes.Repeat([]byte{4}, 1452), bytes.Repeat([]byte{5}, 1452), bytes.Repeat([]byte{6}, 100), bytes.Repeat([]byte{7}, 600)}
				if err = l.sendBatch(packets, receiver.LocalAddr().(*net.UDPAddr), sender.LocalAddr().(*net.UDPAddr)); err != nil {
					t.Fatal(err)
				}
				_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
				for _, want := range packets {
					got := make([]byte, 1500)
					n, _, err := receiver.ReadFromUDP(got)
					if err != nil || !bytes.Equal(got[:n], want) {
						t.Fatalf("datagram %d: %v", n, err)
					}
				}
				if calls := l.sendCalls.Load(); calls != 1 {
					t.Fatalf("mixed datagram sizes required %d send calls, want 1", calls)
				}
				t.Logf("GSO disabled=%v", l.gsoDisabled.Load())
			})
		}
	}
}
