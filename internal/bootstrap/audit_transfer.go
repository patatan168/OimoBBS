// 元controlの連続prefixと日別要約を検査値で結び、移管完了の証明を同期保存する。
package bootstrap

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"time"
)

// auditTransfer は元の値を含まない内部証明。削除許可や提出用署名ではない。
type auditTransfer struct {
	Schema      uint32      `json:"schema_version"`
	Kind        string      `json:"kind"`
	Owner       domain.ID   `json:"owner_id"`
	OwnerKind   string      `json:"owner_kind"`
	Generation  domain.U64  `json:"source_generation"`
	BaseSeq     domain.U64  `json:"source_base_seq"`
	Sequence    domain.U64  `json:"source_seq"`
	SourceHash  domain.Hash `json:"source_sha256_chain"`
	Entries     domain.U64  `json:"entry_count"`
	SummaryHash domain.Hash `json:"summary_sha256_chain"`
	Since       domain.Time `json:"required_since_ns"`
	Imported    domain.Time `json:"imported_at_ns"`
}

// auditChain は順序付きの固定長前値とデータを結合する。元JSONや秘密を証明へ転記しない。
func auditChain(prior domain.Hash, parts ...[]byte) domain.Hash {
	h := sha256.New()
	h.Write(prior[:])
	for _, part := range parts {
		h.Write(part)
	}
	var result domain.Hash
	copy(result[:], h.Sum(nil))
	return result
}

func newAuditTransfer(log *store.ControlLog, kind string, since time.Time) auditTransfer {
	h := log.HistoryHeader()
	return auditTransfer{Schema: 1, Kind: "source_transfer", Owner: h.Owner, OwnerKind: kind, Generation: domain.U64(h.Generation), BaseSeq: domain.U64(h.BaseSeq), Sequence: domain.U64(h.BaseSeq), Since: domain.Time(since.UnixNano())}
}

// advance は保存成功済みの要約だけを件数・検査値へ含める。すべてのsource frameで連番を確認する。
func (p *auditTransfer) advance(rec store.Record, op store.ControlOperation, entry *AuditEntry) error {
	if op.ExpectedSeq != p.Sequence || op.Seq != p.Sequence+1 {
		return store.ErrCorrupt
	}
	next := *p
	next.Sequence = op.Seq
	next.SourceHash = auditChain(p.SourceHash, rec.ID[:], rec.JSON)
	if entry != nil {
		raw, e := json.Marshal(entry)
		if e != nil {
			return e
		}
		next.Entries++
		next.SummaryHash = auditChain(p.SummaryHash, raw)
	}
	*p = next
	return nil
}

// validateAuditTransfer は初期化行とは別の固定型を検査し、世代・範囲・保持境界の後退を拒否する。
func validateAuditTransfer(owner domain.ID, kind, day string, old, next json.RawMessage) error {
	var p auditTransfer
	if e := strictjson.Decode(next, &p); e != nil {
		return e
	}
	if p.Schema != 1 || p.Kind != "source_transfer" || p.Owner != owner || p.OwnerKind != kind || p.Generation != 1 || p.BaseSeq != 0 || p.Sequence == 0 || p.SourceHash == (domain.Hash{}) || p.Entries > p.Sequence || (p.Entries == 0) != (p.SummaryHash == (domain.Hash{})) || p.Imported <= 0 || p.Since <= 0 || p.Since > p.Imported || time.Unix(0, int64(p.Imported)).UTC().Format("20060102") != day {
		return store.ErrCorrupt
	}
	if p.Since > p.Imported-domain.Time(auditRetention) {
		return errors.New("audit proof retention is too short")
	}
	if len(old) == 0 {
		return nil
	}
	var before auditTransfer
	if e := strictjson.Decode(old, &before); e != nil {
		return e
	}
	if p.Generation != before.Generation || p.BaseSeq != before.BaseSeq || p.Sequence < before.Sequence || p.Since < before.Since || p.Imported < before.Imported {
		return store.ErrCorrupt
	}
	if p.Sequence == before.Sequence && p.SourceHash != before.SourceHash {
		return store.ErrCorrupt
	}
	if p.Since == before.Since && (p.Entries < before.Entries || p.Sequence == before.Sequence && (p.Entries != before.Entries || p.SummaryHash != before.SummaryHash)) {
		return store.ErrCorrupt
	}
	return nil
}

// proof は日別要約のSync後に呼ぶ。結果不明後の再開は既存行の同一内容を照合して確定する。
func (s *auditSink) proof(p auditTransfer) error {
	now := time.Now().UTC()
	if e := s.open(p.Owner, p.OwnerKind, now.Format("20060102")); e != nil {
		return e
	}
	state := s.log.State()
	if row, ok := state.Rows["import_receipt:source"]; ok {
		var old auditTransfer
		if e := strictjson.Decode(row.Value, &old); e != nil {
			return e
		}
		// 再起動の有界な再走査が既存証明に追いつくまでは、古い証明を維持する。
		if old.Sequence > p.Sequence {
			return nil
		}
		if old.Sequence == p.Sequence && old.SourceHash != p.SourceHash {
			return store.ErrCorrupt
		}
		if old.Sequence == p.Sequence && old.Since < p.Since {
			return nil
		}
		equalOld, equalNew := old, p
		equalOld.Imported = 0
		equalNew.Imported = 0
		if equalOld == equalNew {
			return nil
		}
	}
	p.Imported = domain.Time(now.UnixNano())
	return appendControl(s.log, "audit_transfer", []store.Mutation{mutation("import_receipt", "source", p, nil)}, []string{})
}
