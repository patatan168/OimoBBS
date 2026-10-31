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
	lastSaved time.Time
}

// saved は成功した保存時刻と実Sync待ちを記録し、遅い媒体では短い群への分割を抑える。
// 新しいtimerは作らず、通常の収集上限16msを500msだけ優先する。
func (c *postingCollection) saved(now time.Time, syncDuration time.Duration) {
	c.lastSaved = now
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

// startWindow は最後の保存から100ms以上空いた群の追加待ちを省く。
// フォーム表示では間隔を延ばさず、待機あり・集中受付中は従来の予算を使う。
// 所有列で群の開始時に一度だけ選び、追加収集で待ち時間を復活させない。
func (c *postingCollection) startWindow(now time.Time, queued int) time.Duration {
	window := c.window(now)
	if queued == 0 && !now.Before(c.busyUntil) && !c.lastSaved.IsZero() && now.Sub(c.lastSaved) >= 100*time.Millisecond {
		return 0
	}
	return window
}

// postingCollectionWindow は間隔の空いた群だけ即時保存へ進める。
// それ以外は前群の終了時に確定した基本予算を保持し、集中時の収集方針を選び直さない。
func (b *postingBoard) postingCollectionWindow(queued int) time.Duration {
	if b.collection.startWindow(time.Now(), queued) == 0 {
		return 0
	}
	return b.postBatch.CollectWindow
}
