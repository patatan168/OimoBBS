// 監査要約を有界な単位で同期保存し、成功した範囲だけ索引と元履歴の走査位置へ反映する。
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

type pendingAuditEntry struct {
	entry       AuditEntry
	at          time.Time
	fingerprint [32]byte
	bytes       int
	reason      string
	visible     bool
	fresh       bool
}

type auditImportBatch struct {
	index    *auditIndex
	owner    domain.ID
	kind     string
	cutoff   time.Time
	progress auditTransfer
	entries  []pendingAuditEntry
	known    map[auditIdentity][32]byte
	count    int
	bytes    int
}

// catchUpAuditBatch は別のcursorで最大64frameずつ検査し、保存失敗では元の位置を進めない。
func (r *Repository) catchUpAuditBatch(ctx context.Context, owner domain.ID, kind string, log *store.ControlLog, cursor *store.HistoryCursor, progress *auditTransfer, sink *auditSink, budget *store.HistoryBudget, cutoff time.Time) error {
	for {
		next := cursor.Clone()
		limit := *budget
		limit.Frames = min(limit.Frames, store.MaxCommitFrames)
		frames := limit.Frames
		batch := auditImportBatch{index: r.auditIndex, owner: owner, kind: kind, cutoff: cutoff, progress: *progress, known: map[auditIdentity][32]byte{}}
		err := log.VisitDeltaFrom(ctx, &next, &limit, batch.prepare)
		budget.Bytes = limit.Bytes
		budget.Frames -= frames - limit.Frames
		if saved := batch.save(r, sink); saved != nil {
			return errors.Join(err, saved)
		}
		*cursor, *progress = next, batch.progress
		// 64件の区切りだけで止まった場合は、呼出元全体の予算内で次を処理する。
		if !onlyAuditHistoryBudget(err) || frames == 0 || limit.Frames != 0 || budget.Frames == 0 {
			return err
		}
	}
}

// prepare は未保存の要約・索引候補・証明を隔離し、正本や現在の索引を変更しない。
func (b *auditImportBatch) prepare(rec store.Record, op store.ControlOperation) error {
	var imported *AuditEntry
	var pending *pendingAuditEntry
	entry, ok := auditSummary(b.owner, b.kind, rec, op)
	if ok && op.Committed >= b.progress.Since {
		row, err := b.prepareEntry(entry, time.Unix(0, int64(op.Committed)).UTC(), op.Actor.Reason)
		if err != nil {
			return err
		}
		pending, imported = &row, &entry
	}
	if err := b.progress.advance(rec, op, imported); err != nil {
		return err
	}
	if pending != nil {
		b.entries = append(b.entries, *pending)
		if pending.fresh {
			b.count++
			b.bytes += pending.bytes
			b.known[auditIdentity{entry.Owner, entry.ID}] = pending.fingerprint
		}
	}
	return nil
}

// prepareEntry は同じIDの内容と索引容量を検査し、未公開の要約候補を返す。
func (b *auditImportBatch) prepareEntry(entry AuditEntry, at time.Time, reason string) (pendingAuditEntry, error) {
	raw, err := json.Marshal(entry)
	if err != nil {
		return pendingAuditEntry{}, err
	}
	identity := auditIdentity{entry.Owner, entry.ID}
	fingerprint := sha256.Sum256(raw)
	prior, known := b.index.known[identity]
	if !known {
		prior, known = b.known[identity]
	}
	if known && prior != fingerprint {
		return pendingAuditEntry{}, store.ErrCorrupt
	}
	visible := !at.Before(b.cutoff) && auditVisible(entry)
	fresh := visible && !known
	if fresh && (b.index.count+b.count >= 100000 || b.index.bytes+b.bytes+len(raw) > 64<<20) {
		return pendingAuditEntry{}, errAuditIndexFull
	}
	return pendingAuditEntry{entry: entry, at: at, fingerprint: fingerprint, bytes: len(raw), reason: reason, visible: visible, fresh: fresh}, nil
}

// save は全要約のSync成功後だけメモリ索引を公開する。中断後の再処理は保存済み行を再利用する。
func (b *auditImportBatch) save(r *Repository, sink *auditSink) error {
	entries := make([]AuditEntry, 0, len(b.entries))
	for _, pending := range b.entries {
		entries = append(entries, pending.entry)
	}
	if err := sink.putBatch(entries); err != nil {
		return err
	}
	for _, pending := range b.entries {
		r.checkpoint("audit:durable")
		entry := pending.entry
		if pending.visible {
			b.index.rememberOperation(entry, pending.reason)
		}
		if pending.fresh {
			day := pending.at.Format("20060102")
			b.index.days[day] = append(b.index.days[day], &auditIndexedEntry{entry, pending.at, pending.bytes})
			b.index.known[auditIdentity{entry.Owner, entry.ID}] = pending.fingerprint
			b.index.count++
			b.index.bytes += pending.bytes
		}
	}
	return nil
}
