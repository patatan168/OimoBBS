// 認証済みsnapshot境界以前の監査要約を索引へ戻し、delta走査の起点を復元する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// resumeSnapshotAudit は索引の最初の走査前だけ呼ぶ。部分的な復元では公開一覧を返さない。
func (r *Repository) resumeSnapshotAudit(ctx context.Context, owner domain.ID, kind string, log *store.ControlLog, budget *store.HistoryBudget, archiveBudget *int64, cutoff time.Time) (auditTransfer, error) {
	anchor, ok := r.anchors[owner]
	if !ok {
		return auditTransfer{}, store.ErrCorrupt
	}
	proof, entries, err := r.loadAuditProof(ctx, owner, kind, archiveBudget)
	if err != nil {
		return auditTransfer{}, err
	}
	if proof == nil {
		return auditTransfer{}, store.ErrCorrupt
	}
	if _, err = verifySnapshotAudit(ctx, log, anchor, *proof, entries, budget); err != nil {
		return auditTransfer{}, err
	}
	index := r.auditIndex
	for _, saved := range entries {
		if err = ctx.Err(); err != nil {
			return auditTransfer{}, err
		}
		entry := saved.Summary
		at, err := time.Parse(time.RFC3339Nano, entry.Committed)
		if err != nil {
			return auditTransfer{}, err
		}
		if entry.Sequence > anchor.Sequence || at.Before(cutoff) || at.UnixNano() < int64(anchor.Proof.Since) {
			continue
		}
		raw, err := json.Marshal(entry)
		if err != nil {
			return auditTransfer{}, err
		}
		id := auditIdentity{owner, entry.ID}
		hash := sha256.Sum256(raw)
		if prior, exists := index.known[id]; exists {
			if prior != hash {
				return auditTransfer{}, store.ErrCorrupt
			}
			continue
		}
		if index.count >= 100000 || index.bytes+len(raw) > 64<<20 {
			return auditTransfer{}, errAuditIndexFull
		}
		day := at.UTC().Format("20060102")
		index.days[day] = append(index.days[day], auditIndexedEntry{entry, at, len(raw)})
		index.known[id] = hash
		index.count++
		index.bytes += len(raw)
	}
	return anchor.Proof, nil
}
