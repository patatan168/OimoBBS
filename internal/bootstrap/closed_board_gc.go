// 閉鎖板の通常期限回収は、サイト全体の原本自動整理を無効にしていても継続する。
package bootstrap

import (
	"context"
	"slices"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// sweepClosedBoardOriginalsLocked は閉鎖板を巡回し、一回1本文または64操作まで回収する。
// 進捗は再起動で再走査でき、削除済み署名を照合して同じ原本を再削除しない。
// 通常期限前の回収には、別途署名済みの容量回収許可と保全検査を必要とする。
func (r *Repository) sweepClosedBoardOriginalsLocked(ctx context.Context, now time.Time) (int, error) {
	ids := []domain.ID{}
	for id, b := range r.posting {
		if b.closedAt.Load() != 0 {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return slices.Compare(a[:], b[:]) })
	v := r.closedGCCursor
	v.At = domain.Time(now.UnixNano())
	if v.Board == nil || v.Advance {
		next, found, err := r.findRequiredGCScope(ctx, ids, v.boardID(), uint64(v.Key), v.At)
		if err != nil {
			return 0, err
		}
		if !found {
			next, found, err = r.findRequiredGCScope(ctx, ids, domain.ID{}, 0, v.At)
			if err != nil {
				return 0, err
			}
		}
		if found {
			r.closedGCCursor = applyRequiredGCScope(v, next)
		}
		return 0, nil
	}
	site, _, err := r.requiredGCJob(now)
	if err != nil {
		return 0, err
	}
	next, removed, err := r.runRequiredGCJobLocked(ctx, site, v, now)
	if err == nil {
		r.closedGCCursor = next
	}
	return removed, err
}

// prepareClosedGCBodyOwned は閉鎖から6暦月後を最終期限にし、月末丸めでも期限を超えさせない。
// 保全中のスレッドは次の巡回へ回す。公開本体と原本は別の有界段階で回収する。
func (r *Repository) prepareClosedGCBodyOwned(ctx context.Context, b *postingBoard, v requiredGCState, guard *disclosure.RequiredGCProtection) (requiredGCState, bool, error) {
	at := domain.Time(b.closedAt.Load())
	if at == 0 || v.At < boardClosureDeadline(at) {
		return v, true, nil
	}
	p := b.threads[uint64(v.Key)]
	if p == nil || b.stopped {
		return v, false, store.ErrIncomplete
	}
	if err := b.checkRequiredReclaimClock(v.At); err != nil {
		return v, false, err
	}
	held, err := p.StoragePressureHeld(requiredGCJournals(b), v.At, func(i evidence.RequiredPostingIdentity, now domain.Time) (bool, error) {
		return guard.PairHeld(b.owner, i, now)
	})
	if err != nil {
		return v, false, err
	}
	if held {
		v.Advance = true
		return v, false, nil
	}
	if err := ctx.Err(); err != nil {
		return v, false, err
	}
	if !p.Reclaimed() {
		return v, false, b.saveEarlyReclamation(uint64(v.Key), v.At, "closure", "board_close_expiry")
	}
	if err := b.authorizeClosedPressureOwned(uint64(v.Key), v.At); err != nil {
		return v, false, err
	}
	return v, true, nil
}
