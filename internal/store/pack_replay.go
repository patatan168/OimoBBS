// 確定frameをpackの現在値・追加seq・再送索引・操作要約へ変換する。
package store

import (
	"encoding/json"
	"math"
	"oimobbs/internal/domain"
	"sort"
)

// PackBuilder は単一所有者で使用する復旧候補。Apply失敗後の候補は破棄する。
type PackBuilder struct {
	snapshot PackSnapshot
	records  []ThreadRecord
}

// NewPackBuilder は検証済みbaseの有無に応じた再生器を作る。baseは変更しない。
func NewPackBuilder(base *PackSnapshot) *PackBuilder {
	b := &PackBuilder{}
	if base != nil {
		b.snapshot = *base
		b.snapshot.Origins = append([]domain.U64{}, base.Origins...)
		b.snapshot.Dedup = append([]PackDedup{}, base.Dedup...)
		b.snapshot.Audit = append([]PackAudit{}, base.Audit...)
	}
	return b
}

// Apply はWALの業務遷移を検査し、削除でorigin seqを変えず、本文なしの要約を作る。
func (b *PackBuilder) Apply(f Frame) error {
	next, e := applyFrame(b.snapshot.State, f)
	if e != nil {
		return e
	}
	for _, r := range f.Records {
		op, e := domain.ParseOperation(r.JSON)
		if e != nil {
			return e
		}
		var payload struct {
			Posts []domain.Post `json:"posts"`
		}
		if e = json.Unmarshal(op.Payload, &payload); e != nil {
			return e
		}
		if op.Type != "redact" {
			for range payload.Posts {
				b.snapshot.Origins = append(b.snapshot.Origins, op.Revision)
			}
		}
		if op.Dedup != nil {
			b.snapshot.Dedup = append(b.snapshot.Dedup, PackDedup{r.ID, op.Revision, op.Committed, *op.Dedup})
		}
		if int64(op.Committed) > math.MaxInt64-int64(packAuditRetention) {
			return ErrCorrupt
		}
		ranges := []PackRange{}
		for _, p := range payload.Posts {
			if len(ranges) > 0 && ranges[len(ranges)-1].Last+1 == p.Number {
				ranges[len(ranges)-1].Last = p.Number
			} else {
				ranges = append(ranges, PackRange{p.Number, p.Number})
			}
		}
		b.snapshot.Audit = append(b.snapshot.Audit, PackAudit{op.Revision, r.ID, op.Type, op.Committed, op.Actor, op.Versions, ranges, op.Committed + packAuditRetention})
		b.snapshot.LastOperation = op.Committed
	}
	b.records = append(b.records, frameRecords(f)...)
	b.snapshot.State = next
	return nil
}

// Snapshot は指定した基準時刻に満了した索引を除き、再送キー順へ正規化する。
// 既存baseの基準時刻より時計が戻った場合は、その保持下限を維持する。
func (b *PackBuilder) Snapshot(owner domain.ID, key, generation uint64, at domain.Time) PackSnapshot {
	s := b.snapshot
	s.Owner = owner
	s.Key = key
	s.Generation = generation
	s.At = max(at, s.At)
	s.Dedup = []PackDedup{}
	for _, d := range b.snapshot.Dedup {
		if d.Value.Expires > s.At {
			s.Dedup = append(s.Dedup, d)
		}
	}
	sort.Slice(s.Dedup, func(i, j int) bool { return comparePackDedup(s.Dedup[i], s.Dedup[j]) < 0 })
	s.Audit = []PackAudit{}
	for _, a := range b.snapshot.Audit {
		if a.Expires > s.At {
			s.Audit = append(s.Audit, a)
		}
	}
	return s
}

// Records はこの再生器が適用したdeltaの操作識別を返す。
func (b *PackBuilder) Records() []ThreadRecord {
	out := make([]ThreadRecord, len(b.records))
	for i, r := range b.records {
		out[i] = cloneThreadRecord(r)
	}
	return out
}
