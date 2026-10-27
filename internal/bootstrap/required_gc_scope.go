// 自動原本回収の板/キーを固定順で巡回し、所有者内で一件だけ次候補を選ぶ。
package bootstrap

import (
	"bytes"
	"context"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"slices"
)

// nextRequiredGCScope は板UUID/キー順の次対象を選び、末尾から次の周回へ移る。
func (r *Repository) nextRequiredGCScope(ctx context.Context, v requiredGCState) (requiredGCState, bool, error) {
	ids := make([]domain.ID, 0, len(r.posting))
	for id := range r.posting {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return bytes.Compare(a[:], b[:]) })
	next, found, e := r.findRequiredGCScope(ctx, ids, v.boardID(), uint64(v.Key), v.At)
	if e != nil {
		return v, false, e
	}
	if found {
		return applyRequiredGCScope(v, next), true, nil
	}
	next, found, e = r.findRequiredGCScope(ctx, ids, domain.ID{}, 0, v.At)
	if e != nil || !found {
		return v, false, e
	}
	if v.Round == ^domain.U64(0) {
		return v, false, store.ErrCorrupt
	}
	v.Round++
	return applyRequiredGCScope(v, next), true, nil
}

type requiredGCScope struct {
	board domain.ID
	key   uint64
}

func applyRequiredGCScope(v requiredGCState, next requiredGCScope) requiredGCState {
	v.Board, v.Key = &next.board, domain.U64(next.key)
	v.After, v.Day, v.Proof, v.Advance = 0, 0, domain.Hash{}, false
	return v
}

// findRequiredGCScope は各板所有列の時計床を確認してから、保存位置より後のキーを探す。
func (r *Repository) findRequiredGCScope(ctx context.Context, ids []domain.ID, afterBoard domain.ID, afterKey uint64, at domain.Time) (requiredGCScope, bool, error) {
	for _, id := range ids {
		order := bytes.Compare(id[:], afterBoard[:])
		if order < 0 {
			continue
		}
		floor := uint64(0)
		if order == 0 {
			floor = afterKey
		}
		b := r.posting[id]
		value, e := b.worker.Submit(ctx, func() (any, error) {
			if e := b.checkRequiredReclaimClock(at); e != nil {
				return uint64(0), e
			}
			return nextRequiredGCKey(b, floor), nil
		})
		if e != nil {
			return requiredGCScope{}, false, e
		}
		if key := value.(uint64); key != 0 {
			return requiredGCScope{id, key}, true, nil
		}
	}
	return requiredGCScope{}, false, nil
}

func nextRequiredGCKey(b *postingBoard, after uint64) uint64 {
	var result uint64
	for key := range b.threads {
		if key > after && (result == 0 || key < result) {
			result = key
		}
	}
	return result
}
