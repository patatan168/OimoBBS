// 投稿の短い同時枠競合を、上限を緩めずに空き通知で受け付け直す。
package bootstrap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"oimobbs/internal/waf"
	"runtime"
	"testing"
	"time"
)

func TestWAFTrafficPostingWaitsForShortCapacityContention(t *testing.T) {
	repo := &Repository{}
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
	releases := make([]func(), 32)
	for i := range releases {
		release, d := repo.publicTraffic.AcquireOperation(netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i+1)), waf.Posting, trafficNow())
		if d.Status != 0 {
			t.Fatal(d)
		}
		releases[i] = release
		defer release()
	}
	entered := make(chan struct{}, 4)
	h := repo.trafficHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; w.WriteHeader(204) }), false)
	finished := make(chan int, 4)
	for i := range 4 {
		go func(index int) {
			r := httptest.NewRequest("POST", "/test/bbs.cgi", nil)
			r.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", index+1)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			finished <- w.Code
		}(i)
	}
	// 既存版は4件とも即時503となる。修正版では解放するまで業務処理へ進まない。
	deadline := time.Now().Add(time.Second)
	for repo.publicTraffic.Stats().Posting.Waiting != 4 && len(finished) == 0 && time.Now().Before(deadline) {
		// 待機した4件を実行枠へ数えていないことも確認する。
		if repo.publicTraffic.Stats().Posting.Active < 32 {
			t.Fatal("実行数が上限を迂回した")
		}
		runtime.Gosched()
	}
	if repo.publicTraffic.Stats().Posting.Waiting != 4 {
		t.Fatal("4件の待機を観測できなかった")
	}
	select {
	case code := <-finished:
		t.Fatalf("短い枠競合で即座に拒否した: HTTP %d", code)
	default:
	}
	for i := range 4 {
		releases[i]()
	}
	for range 4 {
		select {
		case code := <-finished:
			if code != 204 {
				t.Fatal(code)
			}
		case <-time.After(time.Second):
			t.Fatal("解放通知後も受け付けられない")
		}
	}
	if len(entered) != 4 || repo.publicTraffic.Stats().Posting.Active != 28 {
		t.Fatal("実行数・解放が不整合")
	}
}
