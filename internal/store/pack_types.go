// packの現在値・索引・操作要約を表現する。非公開値を含むためHTTP DTOへ流用しない。
package store

import (
	"oimobbs/internal/domain"
)

const (
	MaxPackFile    = 64 << 20
	MaxPackPosts   = 65536
	MaxPackEntries = 100000
	packDATTarget  = 64 << 10
)

// PackSnapshot は基準seqの現在値と、元レスの追加seq・保持対象の索引を持つ。
type PackSnapshot struct {
	Owner           domain.ID
	Key, Generation uint64
	At              domain.Time
	State           *domain.Thread
	Origins         []domain.U64
	LastOperation   domain.Time
	Dedup           []PackDedup
	Audit           []PackAudit
}

// PackDedup は受理済み投稿の再送索引。削除台帳のresult=2はpackでは許可しない。
type PackDedup struct {
	ID        domain.ID
	Seq       domain.U64
	Committed domain.Time
	Value     domain.Dedup
}

// PackRange は操作が直接変更したレス番号の閉区間。
type PackRange struct {
	First uint32 `json:"first"`
	Last  uint32 `json:"last"`
}

// PackAudit は本文・接続元を含まない操作要約。
type PackAudit struct {
	Seq       domain.U64      `json:"seq"`
	ID        domain.ID       `json:"operation_id"`
	Type      string          `json:"type"`
	Committed domain.Time     `json:"committed_at_ns"`
	Actor     domain.Actor    `json:"actor"`
	Versions  domain.Versions `json:"policy_versions"`
	Ranges    []PackRange     `json:"target_ranges"`
	Expires   domain.Time     `json:"expires_at_ns"`
}

type packMetadata struct {
	Title         string        `json:"title"`
	Created       domain.Time   `json:"created_at_ns"`
	Expires       domain.Time   `json:"expires_at_ns"`
	Revision      domain.U64    `json:"revision"`
	After         domain.After  `json:"after"`
	Policy        domain.Policy `json:"policy"`
	Move          *string       `json:"move_target"`
	LastOperation domain.Time   `json:"last_operation_at_ns"`
	DATHash       domain.Hash   `json:"dat_sha256"`
}

type packBlock struct {
	first, count, users   uint32
	start, length, offset uint64
	minTime, maxTime      domain.Time
	minSeq, maxSeq        domain.U64
	chunk                 PackChunk
}
