// 大きな検出ログsnapshotだけ短時間まとめ、同じ集計ファイル全体の反復書込みを減らす。
package securitylog

import "time"

const snapshotCoalesceBytes = 64 << 10
const snapshotCoalesceWindow = 100 * time.Millisecond

// coalesces は背景I/O制御のある同一時間帯の大きいsnapshotだけを対象にする。
// 表示・終了・受付列の逼迫を待たせず、従来のOpenと小さいログの保存時期を維持する。
func (l *Log) coalesces(first message, cache *bucketRows) bool {
	return l.admission != nil && first.event != nil && !l.pressure() && cache.info != nil &&
		cache.name == bucket(*first.event) && cache.info.Size() >= snapshotCoalesceBytes
}

// gather はI/O枠を取る前だけ収集する。待っている間も他の背景保存を止めない。
func (l *Log) gather(first message, cache *bucketRows) []message {
	if !l.coalesces(first, cache) {
		return []message{first}
	}
	timer := time.NewTimer(snapshotCoalesceWindow)
	defer timer.Stop()
	return collectSecurityBatch(first, l.queue, timer.C)
}

// collectSecurityBatch は最大256件をまとめ、表示・終了・期限の通知で直ちに返す。
func collectSecurityBatch(first message, input <-chan message, elapsed <-chan time.Time) []message {
	batch := []message{first}
	if first.barrier != nil || first.stop {
		return batch
	}
	for len(batch) < 256 {
		select {
		case next, ok := <-input:
			if !ok {
				return batch
			}
			batch = append(batch, next)
			if next.barrier != nil || next.stop {
				return batch
			}
		case <-elapsed:
			return batch
		}
	}
	return batch
}
