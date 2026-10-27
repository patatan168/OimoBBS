// 同期I/Oをまとめる待ちは低・中負荷で確保し、高負荷時のCPU処理量を維持する。
package bootstrap

import "time"

// postingCollection は板所有列だけが更新する受付数。予約や拒否判定には使用しない。
// 250msに96操作を観測したら500msだけ短い待ちにし、持続負荷ではその期限を更新する。
type postingCollection struct {
	start     time.Time
	count     int
	busyUntil time.Time
	slowUntil time.Time
}

// saved は成功した保存の実Sync待ちだけを観測し、遅い媒体では短い群への分割を抑える。
// 新しいtimerは作らず、通常の収集上限16msを500msだけ優先する。
func (c *postingCollection) saved(now time.Time, syncDuration time.Duration) {
	if syncDuration >= 8*time.Millisecond {
		c.slowUntil = now.Add(500 * time.Millisecond)
	}
}

// note は実際に収集した操作だけを数え、同じ群の保存再試行を重複計上しない。
func (c *postingCollection) note(now time.Time, count int) {
	if c.start.IsZero() || now.Sub(c.start) >= 250*time.Millisecond || now.Before(c.start) {
		c.start, c.count = now, 0
	}
	c.count += count
	if c.count >= 96 {
		c.busyUntil = now.Add(500 * time.Millisecond)
	}
}

func (c *postingCollection) window(now time.Time) time.Duration {
	if now.Before(c.busyUntil) && !now.Before(c.slowUntil) {
		return 2 * time.Millisecond
	}
	return 16 * time.Millisecond
}
