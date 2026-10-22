// 旧境界を完全照合した後でだけ、保持下限を進めた境界・最新証明を再計算する。
package bootstrap

import (
	"context"
	"errors"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// renewAuditBoundary は保存を書き換えない。旧prefixの欠落を新期限で隠すことを禁止する。
func renewAuditBoundary(ctx context.Context, log *store.ControlLog, anchor candidateOwner, proof auditTransfer, entries map[domain.ID]auditStoredEntry, at time.Time, budget *store.HistoryBudget) (candidateOwner, auditTransfer, error) {
	fail := func(err error) (candidateOwner, auditTransfer, error) { return candidateOwner{}, auditTransfer{}, err }
	since := domain.Time(at.Add(-auditRetention).UnixNano())
	if at.After(time.Now()) || since <= 0 || since < anchor.Proof.Since || domain.Time(at.UnixNano()) < proof.Imported {
		return fail(errors.New("audit retention clock regression"))
	}
	result, err := verifySnapshotAudit(ctx, log, anchor, proof, entries, budget)
	if err != nil {
		return fail(err)
	}
	if !result.Complete {
		return fail(errors.New("audit transfer must be complete before retention renewal"))
	}
	nextAnchor, nextProof := anchor, proof
	for _, p := range []*auditTransfer{&nextAnchor.Proof, &nextProof} {
		p.Since = since
		p.Imported = domain.Time(at.UnixNano())
		p.Entries, p.SummaryHash, err = auditPrefixDigest(ctx, *p, entries)
		if err != nil {
			return fail(err)
		}
	}
	// 新しい起点から現行deltaを再照合し、source chainと期限内要約の連続性を確認する。
	if _, err = verifySnapshotAudit(ctx, log, nextAnchor, nextProof, entries, budget); err != nil {
		return fail(err)
	}
	return nextAnchor, nextProof, nil
}
