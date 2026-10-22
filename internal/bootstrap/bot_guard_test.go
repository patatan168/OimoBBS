// 自動Bot停止の固定窓・再送・共有回線・容量・モード変更を検証する。
package bootstrap

import (
	"fmt"
	"oimobbs/internal/domain"
	"sync"
	"testing"
	"time"
)

func botHash(n int) domain.Hash {
	var h domain.Hash
	h[0], h[1] = byte(n), byte(n>>8)
	return h
}

func TestBotGuardAutomaticStopAndRecovery(t *testing.T) {
	var g botGuard
	now := time.Unix(1000, 0)
	subject := botHash(1)
	for i := 0; i < botFailureLimit-1; i++ {
		g.record(subject, botHash(i+1), now)
	}
	if g.check(subject, now) != nil {
		t.Fatal("isolated failures stopped posting")
	}
	for i := 0; i < 20; i++ {
		g.record(subject, botHash(1), now)
	}
	if g.check(subject, now) != nil {
		t.Fatal("same failed request counted again")
	}
	g.record(subject, botHash(botFailureLimit), now)
	if g.check(subject, now) == nil {
		t.Fatal("automatic stop missing")
	}
	if g.check(botHash(2), now) != nil {
		t.Fatal("another cookie stopped")
	}
	g.record(subject, botHash(99), now.Add(botStop-time.Second))
	if g.check(subject, now.Add(botStop)) != nil {
		t.Fatal("stop extended or not released")
	}
	if got := g.stats(now.Add(botStop)); got.Active != 0 || got.Stops != 1 {
		t.Fatal(got)
	}
}

func TestBotGuardModesWindowAndCapacity(t *testing.T) {
	var g botGuard
	now := time.Unix(1000, 0)
	g.configure("observe")
	for i := 1; i <= botFailureLimit; i++ {
		g.record(botHash(1), botHash(i), now)
	}
	if g.check(botHash(1), now) != nil || g.stats(now).Stops != 1 {
		t.Fatal("observe mode")
	}
	g.configure("reject")
	if g.check(botHash(1), now) == nil {
		t.Fatal("mode change cleared state")
	}
	g.configure("off")
	if g.check(botHash(1), now) != nil {
		t.Fatal("off rejects")
	}
	g.record(botHash(2), botHash(1), now)
	if g.stats(now).Subjects != 1 {
		t.Fatal("off records")
	}
	g.configure("reject")
	for i := 2; i <= botSubjectLimit; i++ {
		g.record(botHash(i), botHash(1), now)
	}
	g.record(botHash(botSubjectLimit+1), botHash(1), now)
	if got := g.stats(now); got.Subjects != botSubjectLimit || got.Overflow != 1 {
		t.Fatal(got)
	}
	if g.check(botHash(botSubjectLimit+1), now) != nil {
		t.Fatal("capacity stopped innocent cookie")
	}
	g.record(botHash(botSubjectLimit+1), botHash(1), now.Add(botStop+time.Minute))
	if g.stats(now.Add(botStop+time.Minute)).Subjects != 1 {
		t.Fatal("expired state retained")
	}
	var window botGuard
	for i := 1; i < botFailureLimit; i++ {
		window.record(botHash(1), botHash(i), now)
	}
	window.record(botHash(1), botHash(99), now.Add(botWindow))
	if window.check(botHash(1), now.Add(botWindow)) != nil {
		t.Fatal("old window counted")
	}
}

func TestBotGuardConcurrentAndClock(t *testing.T) {
	var g botGuard
	now := time.Unix(1000, 0)
	var wg sync.WaitGroup
	for i := 1; i <= 50; i++ {
		wg.Go(func() { g.record(botHash(1), botHash(i), now); _ = g.check(botHash(1), now); _ = g.stats(now) })
	}
	wg.Wait()
	if g.stats(now).Stops != 1 {
		t.Fatal("concurrent threshold")
	}
	// 逆行した観測は記録せず、既存の停止時間も延長しない。
	g.record(botHash(1), botHash(100), now.Add(-time.Hour))
	if g.check(botHash(1), now.Add(botStop)) != nil {
		t.Fatal("clock rollback extended stop")
	}
}

func BenchmarkBotGuardNormal(b *testing.B) {
	for _, mode := range []string{"off", "observe", "reject"} {
		b.Run(mode, func(b *testing.B) {
			var g botGuard
			g.configure(mode)
			now := time.Unix(1000, 0)
			b.ReportAllocs()
			for b.Loop() {
				_ = g.check(botHash(1), now)
			}
		})
	}
}

func BenchmarkBotGuardSaturated(b *testing.B) {
	var g botGuard
	now := time.Unix(1000, 0)
	for i := 1; i <= botSubjectLimit; i++ {
		g.record(botHash(i), botHash(1), now)
	}
	b.ReportAllocs()
	for b.Loop() {
		g.record(botHash(botSubjectLimit+1), botHash(1), now)
	}
}

func Example_botGuard() {
	var g botGuard
	now := time.Unix(1000, 0)
	for i := 1; i <= botFailureLimit; i++ {
		g.record(botHash(1), botHash(i), now)
	}
	fmt.Println(g.check(botHash(1), now) != nil, g.check(botHash(1), now.Add(botStop)) == nil)
	// Output: true true
}
