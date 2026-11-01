// snapshot境界の証明・日別要約・現行deltaを結合して監査の連続性を照合する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// verifyAuditPrefixEntries はsource順の要約chainを再構築し、欠落・追加・同seq重複を拒否する。
// entriesは日別正本の型・所有者・期限検査済みであることを前提とする。
func verifyAuditPrefixEntries(ctx context.Context, proof auditTransfer, entries map[domain.ID]auditStoredEntry) error {
	count, hash, err := auditPrefixDigest(ctx, proof, entries)
	if err != nil {
		return err
	}
	if count != proof.Entries || hash != proof.SummaryHash {
		return errors.New("audit summary prefix mismatch")
	}
	return nil
}

// auditPrefixDigest は検証済み正本から指定seq・保持下限の要約chainを再計算する。
func auditPrefixDigest(ctx context.Context, proof auditTransfer, entries map[domain.ID]auditStoredEntry) (domain.U64, domain.Hash, error) {
	if len(entries) > 100000 {
		return 0, domain.Hash{}, store.ErrHistoryBudget
	}
	ordered := make([]AuditEntry, 0, len(entries))
	for id, saved := range entries {
		if err := ctx.Err(); err != nil {
			return 0, domain.Hash{}, err
		}
		a := saved.Summary
		if id != a.ID || a.Owner != proof.Owner || a.OwnerKind != proof.OwnerKind {
			return 0, domain.Hash{}, store.ErrCorrupt
		}
		at, err := time.Parse(time.RFC3339Nano, a.Committed)
		if err != nil {
			return 0, domain.Hash{}, err
		}
		if a.Sequence <= proof.Sequence && at.UnixNano() >= int64(proof.Since) {
			ordered = append(ordered, a)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Sequence < ordered[j].Sequence })
	var hash domain.Hash
	var prior domain.U64
	for _, a := range ordered {
		if err := ctx.Err(); err != nil {
			return 0, domain.Hash{}, err
		}
		if a.Sequence == 0 || a.Sequence <= prior {
			return 0, domain.Hash{}, store.ErrCorrupt
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return 0, domain.Hash{}, err
		}
		hash = auditChain(hash, raw)
		prior = a.Sequence
	}
	return domain.U64(len(ordered)), hash, nil
}

// verifySnapshotAudit は検証済み切替境界から現行deltaまでを照合する部品。
// anchorは切替前の元WAL照合で確定し、snapshotと一緒に永続化されたものだけを渡す。
// 任意の候補metadataを信用するAPIではなく、稼働Repositoryへの接続は別工程。
func verifySnapshotAudit(ctx context.Context, log *store.ControlLog, anchor candidateOwner, proof auditTransfer, entries map[domain.ID]auditStoredEntry, budget *store.HistoryBudget) (AuditTransferOwner, error) {
	verification, err := newSnapshotAuditVerification(ctx, log, anchor, proof, entries)
	if err != nil {
		return AuditTransferOwner{}, err
	}
	return verification.advance(ctx, log, budget)
}

// snapshotAuditVerification は検証済みの境界・要約とdeltaの再開位置を一組で保持する。
// 所有mutex内だけで使用し、検証完了まで一覧へ公開しない。
type snapshotAuditVerification struct {
	anchor     candidateOwner
	proof      auditTransfer
	entries    map[domain.ID]auditStoredEntry
	cursor     store.HistoryCursor
	calculated auditTransfer
	actions    map[auditIdentity]string
}

// newSnapshotAuditVerification はsnapshotとの束縛と二つの要約prefixを照合する。
func newSnapshotAuditVerification(ctx context.Context, log *store.ControlLog, anchor candidateOwner, proof auditTransfer, entries map[domain.ID]auditStoredEntry) (*snapshotAuditVerification, error) {
	h := log.HistoryHeader()
	snapshot, ok := log.SnapshotIdentity()
	if (anchor.Kind != "site" && anchor.Kind != "board") || !ok || h.BaseSeq == 0 || h != anchor.header() || snapshot.Seq != anchor.Sequence || snapshot.Length != anchor.Length || snapshot.SHA != anchor.SHA {
		return nil, store.ErrCorrupt
	}
	base := anchor.Proof
	now := time.Now()
	for _, p := range []auditTransfer{base, proof} {
		raw, err := json.Marshal(p)
		if err != nil {
			return nil, err
		}
		day := time.Unix(0, int64(p.Imported)).UTC().Format("20060102")
		if err = validateAuditTransfer(anchor.Owner, anchor.Kind, day, nil, raw); err != nil {
			return nil, err
		}
		if p.Imported > domain.Time(now.UnixNano()) || p.Since > domain.Time(now.Add(-auditRetention).UnixNano()) {
			return nil, errors.New("audit transfer clock regression")
		}
	}
	if base.Sequence != anchor.Sequence || uint64(base.Generation) >= h.Generation || proof.Generation != base.Generation || proof.BaseSeq != base.BaseSeq || proof.Since != base.Since || proof.Imported < base.Imported || proof.Sequence < base.Sequence || proof.Sequence > log.State().Seq {
		return nil, store.ErrCorrupt
	}
	if err := verifyAuditPrefixEntries(ctx, base, entries); err != nil {
		return nil, err
	}
	if err := verifyAuditPrefixEntries(ctx, proof, entries); err != nil {
		return nil, err
	}
	return &snapshotAuditVerification{anchor: anchor, proof: proof, entries: entries, calculated: base, actions: map[auditIdentity]string{}}, nil
}

// advance は成功済みframeの位置とchainを残し、有界な再取得でも同じprefixを読み直さない。
func (v *snapshotAuditVerification) advance(ctx context.Context, log *store.ControlLog, budget *store.HistoryBudget) (AuditTransferOwner, error) {
	anchor, proof, entries := v.anchor, v.proof, v.entries
	result := AuditTransferOwner{Owner: anchor.Owner, Kind: anchor.Kind, SourceSeq: log.State().Seq}
	calculated := &v.calculated
	base := anchor.Proof
	err := log.VisitDeltaFrom(ctx, &v.cursor, budget, func(rec store.Record, op store.ControlOperation) error {
		if op.Seq > proof.Sequence {
			return errAuditProofEnd
		}
		var imported *AuditEntry
		entry, ok := auditSummary(anchor.Owner, anchor.Kind, rec, op)
		if ok && op.Committed >= base.Since {
			saved, exists := entries[entry.ID]
			if !exists {
				return errors.New("audit delta entry missing")
			}
			want, e := json.Marshal(entry)
			if e != nil {
				return e
			}
			got, e := json.Marshal(saved.Summary)
			if e != nil {
				return e
			}
			if string(want) != string(got) {
				return errors.New("audit delta entry mismatch")
			}
			imported = &entry
			if _, known := auditSourceActions[op.Actor.Reason]; entry.Action == "other_admin_operation" && known {
				v.actions[auditIdentity{entry.Owner, entry.ID}] = op.Actor.Reason
			}
		}
		return calculated.advance(rec, op, imported)
	})
	if err != nil && !errors.Is(err, errAuditProofEnd) {
		return result, err
	}
	if calculated.Sequence != proof.Sequence || calculated.SourceHash != proof.SourceHash || calculated.Entries != proof.Entries || calculated.SummaryHash != proof.SummaryHash {
		return result, errors.New("audit delta proof mismatch")
	}
	result.VerifiedSeq = proof.Sequence
	result.Entries = proof.Entries
	result.Complete = proof.Sequence == result.SourceSeq
	return result, nil
}
