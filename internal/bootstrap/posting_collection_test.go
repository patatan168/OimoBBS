// 保存の収集待ちが低・中負荷と継続した高負荷で切り替わり、負荷終了後に戻ることを検査する。
package bootstrap

import (
	"testing"
	"time"
)

func TestPostingCollectionBalancesLowRateAndBusyCPU(t *testing.T) {
	start := time.Unix(1000, 0)
	var c postingCollection
	if got := c.window(start); got != 16*time.Millisecond {
		t.Fatal("initial collection", got)
	}
	// 300操作/秒まではI/Oをまとめる待ちを保つ。
	for i := range 600 {
		now := start.Add(time.Duration(i) * time.Second / 300)
		c.note(now, 1)
		if got := c.window(now); got != 16*time.Millisecond {
			t.Fatal("low rate lost coalescing", i, got)
		}
	}
	// 450操作/秒が続く間は元の短い待ちを維持する。
	for i := range 900 {
		now := start.Add(3*time.Second + time.Duration(i)*time.Second/450)
		c.note(now, 1)
		if i >= 120 && c.window(now) != 2*time.Millisecond {
			t.Fatal("busy owner retained long wait", i)
		}
	}
	end := start.Add(6 * time.Second)
	if c.window(end) != 16*time.Millisecond {
		t.Fatal("high-load state did not expire")
	}
	c.note(end, 1)
	if c.window(end) != 16*time.Millisecond {
		t.Fatal("idle resumption kept busy state")
	}
}

func TestPostingCollectionCountsCollectedOperations(t *testing.T) {
	now := time.Unix(1000, 0)
	var c postingCollection
	c.note(now, 64)
	if c.window(now) != 16*time.Millisecond {
		t.Fatal("single bounded group became busy too early")
	}
	c.note(now.Add(time.Millisecond), 32)
	if c.window(now.Add(time.Millisecond)) != 2*time.Millisecond {
		t.Fatal("collected burst not recognized")
	}
	c.note(now.Add(time.Second), 1)
	if c.window(now.Add(time.Second)) != 16*time.Millisecond {
		t.Fatal("stale burst retained")
	}
}

// 操作数が多くても保存が遅い間はまとめ、短い遅延・CPU仕事量では待ちを増やさない。
func TestPostingCollectionSlowSyncAndRecovery(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, duration := range []time.Duration{0, 8*time.Millisecond - 1, 8 * time.Millisecond, time.Second} {
		var c postingCollection
		c.note(now, 96)
		c.saved(now, duration)
		want := 2 * time.Millisecond
		if duration >= 8*time.Millisecond {
			want = 16 * time.Millisecond
		}
		if got := c.window(now); got != want {
			t.Fatal("Sync threshold", duration, got)
		}
	}
	var c postingCollection
	c.note(now, 96)
	c.saved(now, 9*time.Millisecond)
	c.note(now.Add(499*time.Millisecond), 96)
	if c.window(now.Add(499*time.Millisecond)) != 16*time.Millisecond {
		t.Fatal("pressure expired early")
	}
	if c.window(now.Add(500*time.Millisecond)) != 2*time.Millisecond {
		t.Fatal("fast storage did not recover")
	}
	c.saved(now.Add(500*time.Millisecond), 10*time.Millisecond)
	if c.window(now.Add(501*time.Millisecond)) != 16*time.Millisecond {
		t.Fatal("continued pressure not recognized")
	}
	if c.window(now.Add(2*time.Second)) != 16*time.Millisecond {
		t.Fatal("idle state changed")
	}
}
