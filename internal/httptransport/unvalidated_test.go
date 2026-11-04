// 製品のUDP入口へRetry前のpacketを送り、暗号処理・応答の頻度上限を検査する。
package httptransport

import (
	"encoding/binary"
	"math"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTP3UnvalidatedRepliesAreRateLimited(t *testing.T) {
	front := httptest.NewUnstartedServer(nil)
	defer front.Close()
	cert := httptest.NewTLSServer(nil)
	front.Config.TLSConfig = cert.TLS.Clone()
	cert.Close()
	h3, reason, err := Prepare(front.Config, front.Listener.Addr(), "https://"+front.Listener.Addr().String(), true, 64, 16)
	if err != nil || h3 == nil {
		t.Fatalf("%s %v", reason, err)
	}
	defer h3.Close()
	peer, err := net.Dial("udp4", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	// Initialの暗号文は不要。RetryとVersion Negotiationの生成に使われるheaderを送る。
	initial := binary.BigEndian.AppendUint32([]byte{0xc0}, 1)
	initial = append(initial, 8)
	initial = append(initial, []byte("initial0")...)
	initial = append(initial, 8)
	initial = append(initial, []byte("client00")...)
	initial = append(initial, 0, 17)
	initial = append(initial, make([]byte, 1200-len(initial))...)
	version := append([]byte(nil), initial...)
	binary.BigEndian.PutUint32(version[1:5], 0xface)
	buffer := make([]byte, 1500)
	start := time.Now()
	replies := 0
	for i := range 512 {
		packet := initial
		if i%2 == 1 {
			packet = version
		}
		if _, err := peer.Write(packet); err != nil {
			t.Fatal(err)
		}
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Millisecond))
		if _, err := peer.Read(buffer); err == nil {
			replies++
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	sends := h3.NativeStats().SendCalls
	maximum := 256 + int(math.Ceil(64*elapsed.Seconds()))
	t.Logf("issued=512 replies=%d sends=%d elapsed=%s source_budget=%d", replies, sends, elapsed, maximum)
	if maximum >= 512 {
		t.Fatal("test exceeded the burst-refill observation window")
	}
	if replies == 0 || int(sends) > maximum || h3.NativeStats().Connections != 0 {
		t.Fatal("unvalidated Retry/version flood escaped admission")
	}
}
