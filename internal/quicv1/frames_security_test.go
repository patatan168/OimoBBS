// 認証後のframe解析にも不正入力を与え、状態をまたぐpanicと資源枠の逸脱を検査する。
package quicv1

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// FuzzQUICFrames は各暗号化levelのframeを実際のTLS・stream状態へ入力する。
func FuzzQUICFrames(f *testing.F) {
	for _, data := range [][]byte{{1}, {8, 0}, {15, 0, 0, 0}, {4, 0, 0, 0}, {2, 0, 0, 0, 0}, {6, 0, 0}, {0x18, 1, 0, 8}} {
		f.Add(byte(spaceApplication), data)
	}
	f.Fuzz(func(t *testing.T, space byte, data []byte) {
		if len(data) > 4096 {
			return
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		l := &Listener{cfg: Config{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}, accepted: make(chan *Conn, 1)}
		addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
		c, err := newConn(l, ctx, cancel, addr, addr, []byte("server00"), []byte("client00"), []byte("original"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.tls.Close()
		_, _ = c.frames(int(space%3), data, time.Now())
		if len(c.streams) > 38 || c.queuedBytes > 512<<10 || len(c.pending) > 4096 {
			t.Fatal("frame resource budget exceeded")
		}
	})
}
