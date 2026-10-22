// 大きい非必須記録を圧縮blockの境界で区切り、FIFOと件数・予約byteの上限を保つ。
package evidence

import (
	"context"
	"slices"
	"time"
)

// gatherOptionalBatch は最大256件・元JSON4MiBを収集する。持越し行の予約は保存後まで返さない。
// 途中のbyte境界だけ64件へ切りそろえ、余りと次の一行を次batchの先頭へ戻す。
func (q *OptionalQueue) gatherOptionalBatch(ctx context.Context, first *optionalQueuedRecord, carry []*optionalQueuedRecord) ([]*optionalQueuedRecord, []*optionalQueuedRecord) {
	batch := []*optionalQueuedRecord{first}
	size := first.bytes
	timer := time.NewTimer(q.batchWait)
	defer timer.Stop()
	for len(batch) < MaxOptionalBatch {
		var entry *optionalQueuedRecord
		if len(carry) > 0 {
			entry, carry = carry[0], carry[1:]
		} else {
			select {
			case next, ok := <-q.queue:
				if !ok {
					return batch, carry
				}
				entry = next
			case <-timer.C:
				return batch, carry
			case <-ctx.Done():
				return batch, carry
			}
		}
		if entry.bytes > maxOptionalBatchRecordBytes-size {
			keep := alignedOptionalCount(len(batch))
			next := slices.Clone(batch[keep:])
			next = append(next, entry)
			next = append(next, carry...)
			return batch[:keep], next
		}
		size += entry.bytes
		batch = append(batch, entry)
	}
	return batch, carry
}
