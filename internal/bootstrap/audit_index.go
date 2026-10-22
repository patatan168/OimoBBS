// 日別監査の同期保存後にだけ差分位置と検索用メモリ索引を進める。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"sort"
	"time"
)

var errAuditCatchUp = errors.New("audit catch-up budget exceeded")
var errAuditIndexFull = errors.New("audit index capacity exceeded")

type auditIdentity struct{ owner, id domain.ID }

type auditIndexedEntry struct {
	entry AuditEntry
	at    time.Time
	bytes int
}
type auditIndex struct {
	details      map[auditIdentity]string
	proved       map[domain.ID]auditTransfer
	transfers    map[domain.ID]*auditTransfer
	since        time.Time
	known        map[auditIdentity][32]byte
	cursors      map[domain.ID]*store.HistoryCursor
	days         map[string][]auditIndexedEntry
	count, bytes int
}

// enableAuditStorage は日別fileを作る前に旧readerの書込みを禁止する。表示用revisionは変えない。
func (r *Repository) enableAuditStorage() error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if site.MinimumReader >= 10 {
		return nil
	}
	site.MinimumReader = 10
	if e := appendControl(r.site, "audit_storage_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
		r.stopped = true
		return e
	}
	return nil
}

// catchUpAudit はサイトmutex保持下で呼ぶ。取消・予算超過でも確定済み移管分の位置は保持する。
// 再起動時は正本を再照合する。sourceの圧縮・削除を許可する永続watermarkではない。
func (r *Repository) catchUpAudit(ctx context.Context, budget *store.HistoryBudget) (err error) {
	if err = r.available(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = r.enableAuditStorage(); err != nil {
		return err
	}
	if r.auditIndex == nil {
		r.auditIndex = &auditIndex{proved: map[domain.ID]auditTransfer{}, since: time.Now().Add(-auditRetention), transfers: map[domain.ID]*auditTransfer{}, known: map[auditIdentity][32]byte{}, cursors: map[domain.ID]*store.HistoryCursor{}, days: map[string][]auditIndexedEntry{}}
	}
	index := r.auditIndex
	cutoff := time.Now().Add(-auditRetention)
	// 表示期限の過ぎた項目だけメモリから除外する。日別正本とsourceは削除しない。
	for day, rows := range index.days {
		kept := rows[:0]
		for _, row := range rows {
			if row.at.Before(cutoff) {
				delete(index.known, auditIdentity{row.entry.Owner, row.entry.ID})
				delete(index.details, auditIdentity{row.entry.Owner, row.entry.ID})
				index.count--
				index.bytes -= row.bytes
			} else {
				kept = append(kept, row)
			}
		}
		clear(rows[len(kept):])
		if len(kept) == 0 {
			delete(index.days, day)
		} else {
			index.days[day] = kept
		}
	}
	sink := auditSink{root: filepath.Join(r.cfg.DataDir, "audit"), remember: r.rememberAuditLog}
	defer func() { err = errors.Join(err, sink.close()) }()
	archiveBudget := int64(64 << 20)
	scan := func(owner domain.ID, kind string, log *store.ControlLog) error {
		cursor := index.cursors[owner]
		if cursor == nil {
			cursor = &store.HistoryCursor{}
			index.cursors[owner] = cursor
		}
		progress := index.transfers[owner]
		if progress == nil {
			p := newAuditTransfer(log, kind, index.since)
			if log.HistoryHeader().BaseSeq != 0 {
				var err error
				p, err = r.resumeSnapshotAudit(ctx, owner, kind, log, budget, &archiveBudget, cutoff)
				if err != nil {
					return err
				}
			}
			progress = &p
			index.transfers[owner] = progress
		}
		e := log.VisitDeltaFrom(ctx, cursor, budget, func(rec store.Record, op store.ControlOperation) error {
			var imported *AuditEntry
			at := time.Unix(0, int64(op.Committed)).UTC()
			entry, ok := auditSummary(owner, kind, rec, op)
			if ok && op.Committed >= progress.Since {
				raw, e := json.Marshal(entry)
				if e != nil {
					return e
				}
				identity := auditIdentity{entry.Owner, entry.ID}
				fingerprint := sha256.Sum256(raw)
				prior, known := index.known[identity]
				if known && prior != fingerprint {
					return store.ErrCorrupt
				}
				visible := !at.Before(cutoff)
				if !known && visible && (index.count >= 100000 || index.bytes+len(raw) > 64<<20) {
					return errAuditIndexFull
				}
				if e = sink.put(entry); e != nil {
					return e
				}
				r.checkpoint("audit:durable")
				imported = &entry
				if visible {
					index.rememberOperation(entry, op.Actor.Reason)
				}
				if !known && visible {
					day := at.Format("20060102")
					index.days[day] = append(index.days[day], auditIndexedEntry{entry, at, len(raw)})
					index.known[identity] = fingerprint
					index.count++
					index.bytes += len(raw)
				}
			}
			return progress.advance(rec, op, imported)
		})
		if e != nil && !errors.Is(e, store.ErrHistoryBudget) {
			return e
		}
		if progress.Sequence > progress.BaseSeq && index.proved[owner] != *progress {
			if err := sink.proof(*progress); err != nil {
				return err
			}
			r.checkpoint("audit:proof_durable")
			index.proved[owner] = *progress
		}
		return e
	}
	if err = scan(siteID(r.site.State()), "site", r.site); err != nil {
		return err
	}
	ids := make([]domain.ID, 0, len(r.posting))
	for id := range r.posting {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	for _, id := range ids {
		b := r.posting[id]
		if _, err = b.worker.Submit(ctx, func() (any, error) { return nil, scan(id, "board", b.control) }); err != nil {
			return err
		}
	}
	return nil
}

// auditMatches は板自身の操作に加え、サイト側で確定した板作成・機能有効化も拾う。
func auditMatches(entry AuditEntry, q auditQuery) bool {
	if q.Action != "" && entry.Action != q.Action || q.Actor != (domain.ID{}) && (entry.ActorID == nil || *entry.ActorID != q.Actor) {
		return false
	}
	if len(q.Boards) > 0 {
		for _, id := range q.Boards {
			single := q
			single.Boards = nil
			single.Board = id
			if auditMatches(entry, single) {
				return true
			}
		}
		return false
	}
	if q.Board == (domain.ID{}) || entry.Owner == q.Board {
		return true
	}
	if entry.Action != "board_provisioning" && entry.Action != "board_activated" && entry.Action != "board_settings_enable" && entry.Action != "denial_rules_enable" && entry.Action != "thread_settings_enable" && entry.Action != "local_rules_enable" {
		return false
	}
	for _, target := range entry.Targets {
		if target == q.Board.String() {
			return true
		}
	}
	return false
}

// collectAudit は日別索引から期間候補を選び、完全な検索結果だけ返す。
func (r *Repository) collectAudit(ctx context.Context, q auditQuery) ([]AuditEntry, error) {
	budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
	if e := r.catchUpAudit(ctx, &budget); e != nil {
		if errors.Is(e, store.ErrHistoryBudget) {
			return nil, errAuditCatchUp
		}
		return nil, e
	}
	selected := []auditIndexedEntry{}
	size := 0
	first, last := q.From.UTC().Format("20060102"), q.To.UTC().Format("20060102")
	for day, rows := range r.auditIndex.days {
		if day < first || day > last {
			continue
		}
		for _, row := range rows {
			row.entry = r.auditIndex.describeEntry(row.entry)
			if e := ctx.Err(); e != nil {
				return nil, e
			}
			if row.at.Before(q.From) || !row.at.Before(q.To) || !auditMatches(row.entry, q) {
				continue
			}
			size += row.bytes
			if len(selected) >= 2000 || size > 2<<20 {
				return nil, store.ErrHistoryBudget
			}
			selected = append(selected, row)
		}
	}
	sort.Slice(selected, func(i, j int) bool {
		a, b := selected[i], selected[j]
		if !a.at.Equal(b.at) {
			return a.at.After(b.at)
		}
		return a.entry.ID.String() < b.entry.ID.String()
	})
	rows := make([]AuditEntry, 0, len(selected))
	for _, row := range selected {
		rows = append(rows, row.entry)
	}
	return rows, nil
}
