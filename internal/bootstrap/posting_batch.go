// 公開返信の候補・受理枠・容量予約を所有列で一括確定し、HTTPへ未確定結果を渡さない。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

type postingGroup struct {
	owner    *postingBoard
	batch    *app.PostingBatch
	ctx      context.Context
	key      uint64
	results  map[domain.ID]store.CommitResult
	settlers []func(store.CommitResult) error
	releases []func()
	rebuild  bool
	current  int
	guards   []postingGuard
	rejected map[int]error
}

type postingGuard struct {
	index int
	check func() error
}

var errPostingRebuild = errors.New("rebuild posting batch after cancellation")

// submitPostingBatch は公開返信だけを同じthreadの連続グループへ入れる。
// スレ立て/非公開通報/通常所有操作は既存の直列保存で境界を区切る。
func (r *Repository) submitPostingBatch(ctx context.Context, b *postingBoard, key uint64, run func() (any, error)) (any, error) {
	if key == 0 || b.postBatch == nil {
		return r.submitPosting(ctx, b.worker, run)
	}
	release := r.postingIO.holdPost()
	defer release()
	return b.worker.SubmitBatch(ctx, b.postBatch, key, run)
}

// runPostingBatch は候補を順番に作り、一括保存と受理枠の確定後に元の結果へ戻す。
func (b *postingBoard) runPostingBatch(operations []board.BatchOperation) []board.BatchResult {
	return b.runPostingReadyBatch(operations, nil)
}

// runPostingReadyBatchは保存前に到着済みの続きも収集する。収集待ちはせず所有列の上限を守る。
func (b *postingBoard) runPostingReadyBatch(operations []board.BatchOperation, collect func() []board.BatchOperation) []board.BatchResult {
	g := &postingGroup{owner: b, batch: &app.PostingBatch{}, results: map[domain.ID]store.CommitResult{}, rejected: map[int]error{}}
	b.group = g
	defer func() { b.group = nil }()
	results := make([]board.BatchResult, len(operations))
	pending := make([]int, len(operations))
	for i := range pending {
		pending[i] = i
	}
	for len(pending) > 0 {
		g.rebuild = false
		for cursor := 0; cursor < len(pending); cursor++ {
			i := pending[cursor]
			if e := g.rejected[i]; e != nil {
				results[i] = board.BatchResult{Err: e}
			} else if g.rebuild {
				results[i] = board.BatchResult{Err: errPostingRebuild}
			} else {
				g.ctx = operations[i].Context
				g.current = i
				results[i].Value, results[i].Err = operations[i].Run()
				if operations[i].Complete != nil && completedWithoutStorage(results[i]) {
					operations[i].Complete(results[i].Value, results[i].Err)
				}
			}
			if cursor == len(pending)-1 && collect != nil {
				for _, op := range collect() {
					pending = append(pending, len(operations))
					operations = append(operations, op)
					results = append(results, board.BatchResult{})
				}
			}
		}
		g.flush()
		next := make([]int, 0, len(pending))
		for _, i := range pending {
			if g.needsRebuild(results[i]) {
				next = append(next, i)
			}
		}
		pending = next
	}
	for i := range results {
		switch value := results[i].Value.(type) {
		case RepositoryPostingResult:
			results[i].Value = g.resolve(value)
		case LegacyFormResult:
			value.RepositoryPostingResult = g.resolve(value.RepositoryPostingResult)
			results[i].Value = value
		}
	}
	return results
}

// completedWithoutStorage は確認/入力拒否等の確定した未保存結果だけを先に返す。
// 後続の確認済み投稿を列へ進め、一括保存の完了待ちで確認往復を直列化しない。
func completedWithoutStorage(result board.BatchResult) bool {
	if result.Err != nil {
		return !errors.Is(result.Err, errPostingRebuild)
	}
	var value RepositoryPostingResult
	switch v := result.Value.(type) {
	case editingForm:
		return true
	case RepositoryPostingResult:
		value = v
	case LegacyFormResult:
		value = v.RepositoryPostingResult
	default:
		return false
	}
	return value.Status == store.NotWritten && !errors.Is(value.Err, app.ErrPostingPrepared) && !errors.Is(value.Err, errPostingRebuild)
}

// hasPrepared は未確定候補があるときだけ容量予約を一括確定まで保持する。
func (g *postingGroup) hasPrepared() bool { return g.batch.Count() > 0 }

// flush は三つの耐久境界の結果で受理枠を確定/返却し、容量を一度だけ解放する。
func (g *postingGroup) flush() {
	ids := g.batch.IDs()
	if len(ids) == 0 {
		return
	}
	var saved store.CommitResult
	for _, guard := range g.guards {
		if e := guard.check(); e != nil {
			g.rejected[guard.index] = e
			g.rebuild = true
		}
	}
	if g.rebuild {
		g.batch.Discard()
		saved = store.CommitResult{Status: store.NotWritten, Err: errPostingRebuild}
	} else {
		saved = g.batch.Commit()
	}
	if saved.Status == store.NotWritten && (errors.Is(saved.Err, context.Canceled) || errors.Is(saved.Err, context.DeadlineExceeded)) {
		g.rebuild = true
	}
	for _, settle := range g.settlers {
		if e := settle(saved); e != nil {
			g.owner.stopped = true
			saved = store.CommitResult{Status: store.Unknown, Err: e}
		}
	}
	if saved.Status == store.Unknown {
		g.owner.stopped = true
		g.rebuild = false
	}
	for _, id := range ids {
		g.results[id] = saved
		if saved.Status == store.Durable || saved.Status == store.Unknown {
			g.owner.operations[id] = g.key
		}
	}
	for _, release := range g.releases {
		release()
	}
	g.batch = &app.PostingBatch{}
	g.settlers = nil
	g.releases = nil
	g.guards = nil
}

// needsRebuild は未保存の取消グループだけを作り直す。既に保存した別グループは再実行しない。
func (g *postingGroup) needsRebuild(result board.BatchResult) bool {
	if errors.Is(result.Err, errPostingRebuild) {
		return true
	}
	var value RepositoryPostingResult
	switch v := result.Value.(type) {
	case RepositoryPostingResult:
		value = v
	case LegacyFormResult:
		value = v.RepositoryPostingResult
	default:
		return false
	}
	if errors.Is(value.Err, errPostingRebuild) {
		return true
	}
	if !errors.Is(value.Err, app.ErrPostingPrepared) {
		return false
	}
	saved := g.results[value.OperationID]
	if errors.Is(saved.Err, errPostingRebuild) {
		return true
	}
	return saved.Status == store.NotWritten && (errors.Is(saved.Err, context.Canceled) || errors.Is(saved.Err, context.DeadlineExceeded))
}

// resolve は未確定/同一候補の再送結果を、実際の耐久結果へ置き換える。
func (g *postingGroup) resolve(value RepositoryPostingResult) RepositoryPostingResult {
	if !errors.Is(value.Err, app.ErrPostingPrepared) {
		return value
	}
	saved, ok := g.results[value.OperationID]
	if !ok {
		panic("posting batch lost prepared result")
	}
	value.CommitResult = saved
	return value
}
