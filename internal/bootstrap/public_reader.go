// 板の保存列と独立した公開スレッド索引を参照する。
package bootstrap

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
)

// publicSnapshot は確定済みDATを取得する。公開リースの検査は送信側へ残す。
func (b *postingBoard) publicSnapshot(key uint64, now domain.Time) (*app.PostingSnapshot, int) {
	if key == reportReceiptKey && b.receipt.Load() != nil {
		return b.receipt.Load(), 200
	}
	value, ok := b.publicReaders.Load(key)
	if !ok {
		return nil, 404
	}
	return value.(*app.PublicReader).Snapshot(now)
}
