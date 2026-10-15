// 停止中の保守CLI向けに、保存した移管証明を元WAL・日別要約の両方と照合する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// AuditTransferOwner は移管検証の結果。設定値・hash・操作者の秘密は返さない。
type AuditTransferOwner struct {
	Owner       domain.ID  `json:"owner_id"`
	Kind        string     `json:"owner_kind"`
	SourceSeq   domain.U64 `json:"source_seq"`
	VerifiedSeq domain.U64 `json:"verified_seq"`
	Entries     domain.U64 `json:"entry_count"`
	Complete    bool       `json:"complete"`
}

// AuditTransferReport のCompleteは現在seqまでの照合成功。source削除を許可する値ではない。
type AuditTransferReport struct {
	Complete bool                 `json:"complete"`
	Owners   []AuditTransferOwner `json:"owners"`
}

// VerifyAuditTransfer は保存を変更せず検査する。Repositoryの排他と板workerを使い、途中結果を返さない。
func (r *Repository) VerifyAuditTransfer(ctx context.Context) (AuditTransferReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verifyAuditTransferLocked(ctx)
}

// verifyAuditTransferLocked はサイト排他保持下で候補作成と同じ照合を共有する。
func (r *Repository) verifyAuditTransferLocked(ctx context.Context) (AuditTransferReport, error) {
	if e := r.available(); e != nil {
		return AuditTransferReport{}, e
	}
	if e := ctx.Err(); e != nil {
		return AuditTransferReport{}, e
	}
	budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
	archiveBudget := int64(64 << 20)
	result := AuditTransferReport{Complete: true, Owners: []AuditTransferOwner{}}
	verify := func(owner domain.ID, kind string, log *store.ControlLog) error {
		row, e := r.verifyAuditOwner(ctx, owner, kind, log, &budget, &archiveBudget)
		if e != nil {
			return e
		}
		result.Owners = append(result.Owners, row)
		result.Complete = result.Complete && row.Complete
		return nil
	}
	if e := verify(siteID(r.site.State()), "site", r.site); e != nil {
		return AuditTransferReport{}, e
	}
	ids := make([]domain.ID, 0, len(r.boards))
	for id := range r.boards {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	for _, id := range ids {
		var e error
		if b := r.posting[id]; b != nil {
			_, e = b.worker.Submit(ctx, func() (any, error) { return nil, verify(id, "board", b.control) })
		} else {
			e = verify(id, "board", r.boards[id])
		}
		if e != nil {
			return AuditTransferReport{}, e
		}
	}
	return result, nil
}

// loadAuditProof は日別正本を無変更で検査し、最も先までの証明と要約を有界に取得する。
func (r *Repository) loadAuditProof(ctx context.Context, owner domain.ID, kind string, budget *int64) (*auditTransfer, map[domain.ID]auditStoredEntry, error) {
	root := filepath.Join(r.cfg.DataDir, "audit", owner.String())
	if e := privatePath(root, true); os.IsNotExist(e) {
		return nil, nil, nil
	} else if e != nil {
		return nil, nil, e
	}
	days, e := os.ReadDir(root)
	if e != nil {
		return nil, nil, e
	}
	var proof *auditTransfer
	entries := map[domain.ID]auditStoredEntry{}
	for _, day := range days {
		if e = ctx.Err(); e != nil {
			return nil, nil, e
		}
		h, _, e := auditInitial(owner, kind, day.Name())
		if e != nil {
			return nil, nil, e
		}
		path := filepath.Join(root, day.Name())
		// サイズは検査前に上限を適用する。検証済みfile以外は参照しない。
		if e = privatePath(filepath.Join(path, "control-000001.wal"), false); e != nil {
			return nil, nil, e
		}
		info, e := os.Lstat(filepath.Join(path, "control-000001.wal"))
		if e != nil {
			return nil, nil, e
		}
		if info.Size() > *budget {
			return nil, nil, store.ErrHistoryBudget
		}
		*budget -= info.Size()
		if e = inspectAuditDay(path, h, kind, day.Name(), false, map[domain.ID]bool{}, readerVersion); e != nil {
			return nil, nil, e
		}
		state, e := store.InspectControl(path, 4, owner, h.Key, auditValueValidator(owner, kind, day.Name()))
		if e != nil {
			return nil, nil, e
		}
		for key, row := range state.Rows {
			if key == "import_receipt:source" {
				var p auditTransfer
				if e = strictjson.Decode(row.Value, &p); e != nil {
					return nil, nil, e
				}
				if proof == nil || p.Sequence > proof.Sequence || p.Sequence == proof.Sequence && p.Since > proof.Since {
					proof = &p
				}
			}
			if strings.HasPrefix(key, "audit_entry:") {
				if isThreadAudit(row.Value) {
					continue
				}
				var entry auditStoredEntry
				if e = strictjson.Decode(row.Value, &entry); e != nil {
					return nil, nil, e
				}
				if _, ok := entries[entry.Summary.ID]; ok {
					return nil, nil, store.ErrCorrupt
				}
				if len(entries) >= 100000 {
					return nil, nil, store.ErrHistoryBudget
				}
				entries[entry.Summary.ID] = entry
			}
		}
	}
	return proof, entries, nil
}

var errAuditProofEnd = errors.New("audit proof prefix end")

// verifyAuditOwner は証明範囲を再計算し、必要な全要約の保存内容・件数・順序を照合する。
func (r *Repository) verifyAuditOwner(ctx context.Context, owner domain.ID, kind string, log *store.ControlLog, budget *store.HistoryBudget, archiveBudget *int64) (AuditTransferOwner, error) {
	result := AuditTransferOwner{Owner: owner, Kind: kind, SourceSeq: log.State().Seq}
	proof, entries, e := r.loadAuditProof(ctx, owner, kind, archiveBudget)
	if e != nil {
		return result, e
	}
	if proof == nil {
		return result, nil
	}
	now := time.Now()
	if proof.Imported > domain.Time(now.UnixNano()) || proof.Since > domain.Time(now.Add(-auditRetention).UnixNano()) {
		return result, errors.New("audit transfer clock regression")
	}
	header := log.HistoryHeader()
	if header.BaseSeq != 0 {
		anchor, ok := r.anchors[owner]
		if !ok {
			return result, store.ErrCorrupt
		}
		return verifySnapshotAudit(ctx, log, anchor, *proof, entries, budget)
	}
	if proof.Owner != owner || proof.OwnerKind != kind || uint64(proof.Generation) != header.Generation || uint64(proof.BaseSeq) != header.BaseSeq || proof.Sequence > log.State().Seq {
		return result, store.ErrCorrupt
	}
	if e := verifyAuditPrefixEntries(ctx, *proof, entries); e != nil {
		return result, e
	}
	calculated := newAuditTransfer(log, kind, time.Unix(0, int64(proof.Since)))
	e = log.VisitCommitted(ctx, budget, func(rec store.Record, op store.ControlOperation) error {
		if op.Seq > proof.Sequence {
			return errAuditProofEnd
		}
		var imported *AuditEntry
		entry, ok := auditSummary(owner, kind, rec, op)
		if ok && op.Committed >= proof.Since {
			saved, exists := entries[entry.ID]
			if !exists {
				return errors.New("audit transfer entry missing")
			}
			want, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			got, err := json.Marshal(saved.Summary)
			if err != nil {
				return err
			}
			if !bytes.Equal(want, got) {
				return errors.New("audit transfer entry mismatch")
			}
			imported = &entry
		}
		return calculated.advance(rec, op, imported)
	})
	if e != nil && !errors.Is(e, errAuditProofEnd) {
		return result, e
	}
	if calculated.Sequence != proof.Sequence || calculated.SourceHash != proof.SourceHash || calculated.Entries != proof.Entries || calculated.SummaryHash != proof.SummaryHash {
		return result, errors.New("audit transfer proof mismatch")
	}
	result.VerifiedSeq = proof.Sequence
	result.Entries = proof.Entries
	result.Complete = proof.Sequence == result.SourceSeq
	return result, nil
}
