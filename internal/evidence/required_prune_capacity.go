// 必須原本回収のsnapshot二重保存と削除frameに必要な共通予約量を見積もる。
package evidence

import (
	"oimobbs/internal/store"
	"reflect"
)

// RequiredPruneReservationBytes は現在列のsnapshot二本と最大128行の追加証跡用余力を返す。
// 原本回収と同じ所有排他内で計算し、予約完了まで列を更新しない。
func (j *Journal) RequiredPruneReservationBytes() (uint64, error) {
	if j.stopped || j.log == nil {
		return 0, store.ErrIncomplete
	}
	state, e := store.InspectControl(j.dir, 8, j.owner, j.day, j.validateValue)
	if e != nil {
		return 0, e
	}
	if !reflect.DeepEqual(state, j.log.State()) {
		return 0, store.ErrCorrupt
	}
	h := j.log.HistoryHeader()
	h.Generation++
	h.BaseSeq = j.seq
	raw, e := store.EncodeControlSnapshot(h, state, 6, j.validateValue)
	if e != nil {
		return 0, e
	}
	return 2*uint64(len(raw)) + (4 << 20), nil
}
