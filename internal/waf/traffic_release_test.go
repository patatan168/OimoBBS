// 要求終了時の解放が、設定変更や別要求の判定ロックを待たないことを検査する。
package waf

import (
	"net/netip"
	"testing"
	"time"
)

func TestTrafficReleaseDoesNotWaitForAdmission(t *testing.T) {
	for _, op := range []Operation{Ordinary, Search, Posting, Reports, Authentication} {
		g, now := trafficFixture()
		release, d := g.AcquireOperation(netip.MustParseAddr("192.0.2.1"), op, now)
		if d.Status != 0 {
			t.Fatal(d)
		}
		g.mu.Lock()
		done := make(chan struct{})
		go func() { release(); release(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			g.mu.Unlock()
			<-done
			t.Fatal("release waited for admission mutex", op)
		}
		g.mu.Unlock()
		if stats := g.Stats(); stats.Active != 0 || stats.SearchActive != 0 || stats.Posting.Active != 0 || stats.Reports.Active != 0 || stats.Authentication.Active != 0 {
			t.Fatal(stats)
		}
	}
}
