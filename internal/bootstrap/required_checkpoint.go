// 既存の起動/毎分保守から一日ずつ必須ログの末尾を固定する。
package bootstrap

import (
	"context"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
	"time"
)

// sweepRequiredCheckpointLocked は共通排他内で最大一日の末尾を保存する。
// 先行reader保存、原本Sync、板controlのSyncの順に行い、原本のみ保存済みでも再開する。
func (r *Repository) sweepRequiredCheckpointLocked(ctx context.Context) error {
	ids := make([]domain.ID, 0, len(r.posting))
	for id := range r.posting {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return slices.Compare(a[:], b[:]) })
	for _, id := range ids {
		b := r.posting[id]
		value, e := b.worker.Submit(ctx, func() (any, error) { return b.requiredCheckpointDay(time.Now()), nil })
		if e != nil {
			return e
		}
		day := value.(uint64)
		if day == 0 {
			continue
		}
		if e = r.enableRequiredCheckpointReaderLocked(); e != nil {
			return e
		}
		release, e := r.reservePrivateLossBytes(128 << 10)
		if e != nil {
			return e
		}
		_, e = b.worker.Submit(ctx, func() (any, error) { return nil, b.saveRequiredCheckpoint(day, time.Now()) })
		release()
		return e
	}
	return nil
}

// requiredCheckpointDay は日末を迎えた未固定列、または板への保存未完了列を選ぶ。
func (b *postingBoard) requiredCheckpointDay(now time.Time) uint64 {
	days := make([]uint64, 0, len(b.journals))
	for day := range b.journals {
		days = append(days, day)
	}
	slices.Sort(days)
	for _, day := range days {
		j := b.journals[day]
		if j.CheckpointPending(now) {
			return day
		}
		if event, ok := j.LatestCheckpoint(); ok && !b.requiredCheckpointAnchored(day, event) {
			return day
		}
	}
	return 0
}

// requiredCheckpointAnchored は同じ保存済み署名なら追記を省く。破損行は起動/保存検査で拒否する。
func (b *postingBoard) requiredCheckpointAnchored(day uint64, event evidence.Event) bool {
	row, ok := b.control.State().Rows["evidence_checkpoint:"+fmt.Sprint(day)]
	if !ok {
		return false
	}
	var anchored evidence.Event
	return strictjson.Decode(row.Value, &anchored) == nil && anchored.EventSHA == event.EventSHA
}

// saveRequiredCheckpoint は板所有列で原本の署名と板への独立参照を順にSyncする。
func (b *postingBoard) saveRequiredCheckpoint(day uint64, now time.Time) error {
	if b.stopped {
		return store.ErrIncomplete
	}
	j := b.journals[day]
	if j == nil {
		return store.ErrIncomplete
	}
	event, e := j.Checkpoint(now)
	if e != nil {
		return e
	}
	if b.requiredCheckpointAnchored(day, event) {
		return nil
	}
	e = appendControl(b.control, "required_journal_checkpoint", []store.Mutation{mutation("evidence_checkpoint", fmt.Sprint(day), event, nil)}, []string{})
	if e != nil {
		b.stopped = true
	}
	return e
}

// enableRequiredCheckpointReaderLocked は新署名/板参照より先にreader55をSyncする。
func (r *Repository) enableRequiredCheckpointReaderLocked() error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if site.MinimumReader >= 55 {
		return nil
	}
	site.MinimumReader = 55
	e := appendControl(r.site, "required_journal_checkpoint_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{})
	if e != nil {
		r.stopped = true
	}
	return e
}
