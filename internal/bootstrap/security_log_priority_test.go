// 検出ログが実際のRepositoryで投稿と背景保存の共通I/O枠を使うことを検査する。
package bootstrap

import (
	"context"
	"oimobbs/internal/securitylog"
	"sync"
	"testing"
	"time"
)

func TestSecurityLogSharesPostingIOPriority(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	finishPost := r.postingIO.holdPost()
	defer finishPost()
	finishBackground, e := r.postingIO.beginOptionalWithPressure(context.Background(), func() bool { return true }, nil)
	if e != nil {
		t.Fatal(e)
	}
	var once sync.Once
	releaseBackground := func() { once.Do(finishBackground) }
	defer releaseBackground()
	now := time.Now()
	r.securityLog.Add(securitylog.Event{At: now, Source: "waf", Reason: "traffic_limit", Rejected: true})
	waitForIOWaiter(t, &r.postingIO)
	done := make(chan uint64, 1)
	go func() {
		v, e := r.securityLog.View(now)
		if e != nil {
			t.Error(e)
		}
		done <- v.Rejected
	}()
	select {
	case <-done:
		t.Fatal("別の背景保存を追い越した")
	default:
	}
	releaseBackground()
	select {
	case n := <-done:
		if n != 1 {
			t.Fatal(n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("表示要求が投稿の完了を待った")
	}
}
