// 所有者内の不変な再送履歴を索引化し、期限や本文不一致の判定を省略せず全件走査を避ける。
package store

import "oimobbs/internal/domain"

type threadDedupKey struct {
	mode    string
	keyID   uint32
	subject domain.Hash
	request domain.Hash
}

// dedupLookupKey は明示IDでは本文hashをkeyに含めず、同じIDの本文不一致も元記録へ照合する。
func dedupLookupKey(d *domain.Dedup) (threadDedupKey, bool) {
	if d == nil {
		return threadDedupKey{}, false
	}
	request := d.Request
	if d.Mode == "explicit" {
		if d.RequestID == nil {
			return threadDedupKey{}, false
		}
		request = *d.RequestID
	}
	return threadDedupKey{d.Mode, d.KeyID, d.Subject, request}, true
}

// extendDedupIndex は追記された確定履歴だけを索引へ追加する。保存失敗の候補は含まない。
// 同じkeyの複数世代を保持し、時刻が戻った場合も従来と同じ最初の有効記録を返す。
func (t *ThreadLog) extendDedupIndex() {
	if t.dedupIndex == nil || t.dedupIndexed > len(t.records) {
		t.dedupIndex = make(map[threadDedupKey][]int, len(t.records))
		t.dedupIndexed = 0
	}
	for t.dedupIndexed < len(t.records) {
		index := t.dedupIndexed
		t.dedupIndexed++
		if key, ok := dedupLookupKey(t.records[index].Dedup); ok {
			t.dedupIndex[key] = append(t.dedupIndex[key], index)
		}
	}
}

// replaceRecords はpackで期限満了した私的索引を除く際、旧keyも残さず解放する。
func (t *ThreadLog) replaceRecords(records []ThreadRecord) {
	t.records = records
	t.dedupIndex = nil
	t.dedupIndexed = 0
}
