// 認証済みsnapshot境界以前の監査要約を索引へ戻し、delta走査の起点を復元する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// resumeSnapshotAudit は索引の最初の走査前だけ呼ぶ。部分的な復元では公開一覧を返さない。
func (r *Repository) resumeSnapshotAudit(ctx context.Context, owner domain.ID, kind string, log *store.ControlLog, budget *store.HistoryBudget, archiveBudget *int64, cutoff time.Time) (auditTransfer, error) {
	index := r.auditIndex
	verification := index.resuming[owner]
	if verification == nil {
		verification = r.auditVerified[owner]
		delete(r.auditVerified, owner)
		if verification != nil && verification.anchor.header() != log.HistoryHeader() {
			verification = nil
		}
	}
	if verification == nil {
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
		verification, err = newSnapshotAuditVerification(ctx, log, anchor, *proof, entries)
		if err != nil {
			return auditTransfer{}, err
		}
	}
	// 起動時の検証を引き継ぐ場合も、時計の後退と保持境界を再確認する。
	now := time.Now()
	for _, proof := range []auditTransfer{verification.anchor.Proof, verification.proof} {
		if proof.Imported > domain.Time(now.UnixNano()) || proof.Since > domain.Time(now.Add(-auditRetention).UnixNano()) {
			return auditTransfer{}, errors.New("audit transfer clock regression")
		}
	}
	if index.resuming == nil {
		index.resuming = map[domain.ID]*snapshotAuditVerification{}
	}
	index.resuming[owner] = verification
	if _, err := verification.advance(ctx, log, budget); err != nil {
		return auditTransfer{}, err
	}
	proof, entries := verification.proof, verification.entries
	for _, saved := range entries {
		if err := ctx.Err(); err != nil {
			return auditTransfer{}, err
		}
		entry := saved.Summary
		at, err := time.Parse(time.RFC3339Nano, entry.Committed)
		if err != nil {
			return auditTransfer{}, err
		}
		if !auditVisible(entry) || entry.Sequence > proof.Sequence || at.Before(cutoff) || at.UnixNano() < int64(proof.Since) {
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
		index.days[day] = append(index.days[day], &auditIndexedEntry{entry, at, len(raw)})
		index.known[id] = hash
		index.count++
		index.bytes += len(raw)
	}
	for id, action := range verification.actions {
		index.rememberOperation(AuditEntry{Owner: id.owner, ID: id.id, Action: "other_admin_operation"}, action)
	}
	// 照合済みのdeltaを再走査せず、その直後から通常の取込へ接続する。
	*index.cursors[owner] = verification.cursor
	delete(index.resuming, owner)
	return proof, nil
}
