// 帯域補充と予約期限の時刻を、単調時計の経過時間から得る。
package delivery

import "time"

var schedulerEpoch = time.Now()

// schedulerNow は起点からの経過時間を返し、送信片ごとの壁時計取得を省く。
// 単調時計だけを使う帯域補充・期限専用であり、ログ等の実時刻には使用しない。
func schedulerNow() time.Time {
	return schedulerEpoch.Add(time.Since(schedulerEpoch))
}
