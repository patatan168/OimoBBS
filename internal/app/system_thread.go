// 保存済みの投稿本文を持たない固定案内を、通常の公開送信リースへ接続する。
package app

import (
	"crypto/sha256"
	"encoding/binary"
	"oimobbs/internal/domain"
)

// NewSystemThreadSnapshot は固定案内だけの、件数・公開期限で終了しない公開候補を作る。
// DATは呼出元で完成し、作成後に変更しない。利用者投稿はこの候補へ追加しない。
// 案内は追記でなく置換するため、現在の強いETagがない差分取得には全文を返す。
func NewSystemThreadSnapshot(title string, dat []byte) *PostingSnapshot {
	sum := sha256.Sum256(dat)
	revision := domain.U64(binary.LittleEndian.Uint64(sum[:8]))
	if revision == 0 {
		revision = 1
	}
	s := &PostingSnapshot{Title: title, DAT: dat, CanReply: true, PostCount: 1, Expires: domain.Time(1<<63 - 1), Generation: 1, Revision: revision, LegacyRangeDisabled: true}
	s.gate = &publicationGate{snapshot: s, leases: map[*PublicLease]func(){}}
	return s
}
