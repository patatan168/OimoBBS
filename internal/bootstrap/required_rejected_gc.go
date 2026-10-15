// 未受理原本の24時間回収を起動/毎分の既存期限整理へ接続する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
	"time"
)

// sweepRejectedOriginalsLocked は確定未受理を一回最大128原本回収する。
// 共通lifecycle/Repository排他を保持し、受理原本GCの任意設定に依存しない。
func (r *Repository) sweepRejectedOriginalsLocked(ctx context.Context) (int, error) {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return 0, e
	}
	now := time.Now()
	var guard *disclosure.RequiredGCProtection
	ids := make([]domain.ID, 0, len(r.posting))
	for id := range r.posting {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return slices.Compare(a[:], b[:]) })
	for _, id := range ids {
		b := r.posting[id]
		value, e := b.worker.Submit(ctx, func() (any, error) { return b.hasUnretiredRejections(), nil })
		if e != nil {
			return 0, e
		}
		if !value.(bool) {
			continue
		}
		if guard == nil {
			guard, e = r.requiredReclaimProtection(ctx, site, now)
			if e != nil {
				return 0, e
			}
		}
		value, e = b.worker.Submit(ctx, func() (any, error) {
			return r.reclaimRejectedOriginalsOwned(ctx, b, site, guard, domain.Time(now.UnixNano()))
		})
		if e != nil {
			return 0, e
		}
		if n := value.(int); n != 0 {
			return n, nil
		}
	}
	return 0, nil
}

// hasUnretiredRejections は通常の受理済み板で日別原本の走査を省く。
func (b *postingBoard) hasUnretiredRejections() bool {
	for _, j := range b.journals {
		if app.RejectedConnectionPending(j) {
			return true
		}
	}
	for _, p := range b.threads {
		if p.HasUnretiredRejections() {
			return true
		}
	}
	return false
}

func (r *Repository) reclaimRejectedOriginalsOwned(ctx context.Context, b *postingBoard, site siteState, guard *disclosure.RequiredGCProtection, now domain.Time) (int, error) {
	if b.stopped {
		return 0, store.ErrIncomplete
	}
	if e := b.checkRequiredReclaimClock(now); e != nil {
		return 0, e
	}
	journals := requiredGCJournals(b)

	keys := make([]uint64, 0, len(b.threads))
	for key := range b.threads {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	held := func(i evidence.RequiredPostingIdentity, at domain.Time) (bool, error) {
		return guard.PairHeld(b.owner, i, at)
	}
	for _, key := range keys {
		p := b.threads[key]
		if !p.HasUnretiredRejections() {
			continue
		}
		candidates, e := p.RejectedOriginalCandidates(journals, now, held)
		if e != nil {
			return 0, e
		}
		if len(candidates) == 0 {
			continue
		}
		return r.pruneRejectedOriginalsOwned(ctx, b, site, key, journals, candidates, now, held)
	}
	connectionHeld := func(i evidence.RequiredPostingIdentity, at domain.Time) (bool, error) {
		return guard.RejectedConnectionHeld(b.owner, i, at)
	}
	return r.reclaimRejectedConnectionsOwned(ctx, b, journals, now, connectionHeld)
}

// pruneRejectedConnectionsOwned は同じ保全排他と容量予約で7日期限を回収する。
func (r *Repository) pruneRejectedConnectionsOwned(ctx context.Context, b *postingBoard, j *evidence.Journal, now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error)) (int, error) {
	bytes, e := j.RequiredPruneReservationBytes()
	if e != nil {
		return 0, e
	}
	release, e := r.reservePrivateReclaimBytes(bytes)
	if e != nil {
		return 0, e
	}
	defer release()
	n, e := app.PruneRejectedConnections(ctx, j, now, held)
	if e != nil {
		b.stopped = true
	}
	return n, e
}

// pruneRejectedOriginalsOwned は容量とreader52の先行Syncを終えてから回収を保存する。
func (r *Repository) pruneRejectedOriginalsOwned(ctx context.Context, b *postingBoard, site siteState, key uint64, journals []*evidence.Journal, candidates []evidence.RequiredPostingIdentity, now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error)) (int, error) {
	day, e := nextRequiredGCSourceDay(b, 0, candidates)
	if e != nil || day == 0 {
		return 0, e
	}
	j := b.journals[uint64(day)]
	bytes, e := j.RequiredPruneReservationBytes()
	if e != nil {
		return 0, e
	}
	release, e := r.reservePrivateReclaimBytes(bytes + uint64(len(candidates))*(512<<10))
	if e != nil {
		return 0, e
	}
	defer release()
	if e = ctx.Err(); e != nil {
		return 0, e
	}
	if site.MinimumReader < 52 {
		site.MinimumReader = 52
		if e = appendControl(r.site, "required_rejected_gc_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
			r.stopped = true
			return 0, e
		}
	}
	b.requiredRetirementEnabled = true
	b.requiredRejectedEnabled = true
	p := b.threads[key]
	n, e := p.PruneRequiredOriginalBatch(ctx, journals, j, candidates, now, b.key.Public().(ed25519.PublicKey), held)
	if e != nil && p.StorageStopped() {
		b.stopped = true
	}
	return n, e
}

func (r *Repository) reclaimRejectedConnectionsOwned(ctx context.Context, b *postingBoard, journals []*evidence.Journal, now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error)) (int, error) {
	for _, j := range journals {
		if !app.RejectedConnectionPending(j) {
			continue
		}
		n, e := r.pruneRejectedConnectionsOwned(ctx, b, j, now, held)
		if e != nil || n != 0 {
			return n, e
		}
	}
	return 0, nil
}
