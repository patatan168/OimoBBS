// 公開返信の候補・受理枠・容量予約を所有列で一括確定し、HTTPへ未確定結果を渡さない。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"sync"
	"time"
)

type postingGroup struct {
	owner                  *postingBoard
	batch                  *app.PostingBatch
	ctx                    context.Context
	results                map[domain.ID]store.CommitResult
	settlers               []func(store.CommitResult) error
	releases               []func()
	rebuild                bool
	full                   bool
	current                int
	guards                 []postingGuard
	validations            []postingValidation
	preparations           []*postingPreparation
	preparationQueue       chan *postingPreparation
	preparationWorkers     sync.WaitGroup
	preparationWork        sync.WaitGroup
	preparationWorkerCount int
	preparedResults        map[int]board.BatchResult
	pendingKeys            map[uint64]bool
	preparationBump        domain.U64
	verifiedCaptures       map[domain.Hash][]byte
	guardPruning           *guardPruneCache
	rejected               map[int]error
	completedOperations    int
}

type postingGuard struct {
	index int
	check func() error
}

var errPostingRebuild = errors.New("retry uncommitted posting operation")

// collectPostingBudget は確認往復を保存件数から分け、準備中も含め64件を超えて収集しない。
// 保存が途中で区切られた群は延長せず、確定済み結果を次の収集のために待たせない。
func (b *postingBoard) collectPostingBudget() int {
	g := b.group
	if g == nil {
		// 最初の一操作はWorkerが既に取り出しており、未実行なので保存候補とみなす。
		return board.MaxBatchOperations - 1
	}
	if g.rebuild || g.full || len(g.results) != 0 {
		return 0
	}
	storage := store.MaxCommitFrames - g.batch.Count() - len(g.preparations)
	// 先に返した確認結果も群の終了まで残るため、保持数を従来の64件に制限する。
	return max(0, min(storage, board.MaxBatchOperations-g.completedOperations))
}

// submitPostingBatch は公開返信だけを同じ板の連続グループへ入れる。
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

// runPostingReadyBatchは保存前に到着済みの続きも収集する。確認だけの群を先に返し、保存候補がある群の収集だけを所有列の上限内で行う。
func (b *postingBoard) runPostingReadyBatch(operations []board.BatchOperation, collect func() []board.BatchOperation) []board.BatchResult {
	b.collection.note(time.Now(), len(operations))
	// board.Workerもこのfieldを所有列内だけで読む。次群の開始時に待ち予算を固定する。
	defer func() {
		if b.postBatch != nil {
			b.postBatch.CollectWindow = b.collection.window(time.Now())
		}
	}()
	g := &postingGroup{owner: b, batch: &app.PostingBatch{CommitGroup: b.sharedThreadWAL}, results: map[domain.ID]store.CommitResult{}, rejected: map[int]error{}}
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
			} else if g.rebuild || g.full {
				results[i] = board.BatchResult{Err: errPostingRebuild}
			} else {
				g.ctx = operations[i].Context
				g.current = i
				results[i].Value, results[i].Err = operations[i].Run()
				if operations[i].Complete != nil && completedWithoutStorage(results[i]) {
					operations[i].Complete(results[i].Value, results[i].Err)
					operations[i] = board.BatchOperation{}
					g.completedOperations++
				}
			}
			if cursor == len(pending)-1 && collect != nil && g.hasPrepared() && !g.full {
				added := collect()
				b.collection.note(time.Now(), len(added))
				for _, op := range added {
					pending = append(pending, len(operations))
					operations = append(operations, op)
					results = append(results, board.BatchResult{})
				}
			}
		}
		g.flush()
		for i, result := range g.preparedResults {
			results[i] = result
		}
		clear(g.preparedResults)
		next := make([]int, 0, len(pending))
		for _, i := range pending {
			if g.needsRebuild(results[i]) {
				next = append(next, i)
			} else {
				results[i] = g.completeStored(operations[i], results[i])
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

// completeStored は保存境界の結果が確定した操作だけ返し、HTTPの入力予約を次の群へ持ち越さない。
// 未保存結果の先行通知とは分け、同じ操作のCompleteを二度呼ばない。
func (g *postingGroup) completeStored(operation board.BatchOperation, result board.BatchResult) board.BatchResult {
	if operation.Complete == nil || result.Err != nil {
		return result
	}
	switch value := result.Value.(type) {
	case RepositoryPostingResult:
		if !errors.Is(value.Err, app.ErrPostingPrepared) {
			return result
		}
		result.Value = g.resolve(value)
	case LegacyFormResult:
		if !errors.Is(value.Err, app.ErrPostingPrepared) {
			return result
		}
		value.RepositoryPostingResult = g.resolve(value.RepositoryPostingResult)
		result.Value = value
	default:
		return result
	}
	operation.Complete(result.Value, result.Err)
	return result
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
	return value.Status == store.NotWritten && !errors.Is(value.Err, app.ErrPostingPrepared) && !errors.Is(value.Err, errPostingRebuild) && !errors.Is(value.Err, errPostingPreparing)
}

// hasPrepared は未確定候補があるときだけ容量予約を一括確定まで保持する。
func (g *postingGroup) hasPrepared() bool { return g.batch.Count() > 0 || len(g.preparations) > 0 }

// flush は三つの耐久境界の結果で受理枠を確定/返却し、容量を一度だけ解放する。
func (g *postingGroup) flush() {
	g.finishPreparations()
	g.joinPreparationWorkers()
	ids := g.batch.IDs()
	if len(ids) == 0 {
		g.full = false
		return
	}
	var saved store.CommitResult
	g.validateCandidates()
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
		if saved.Status == store.Durable {
			g.owner.collection.saved(time.Now(), g.batch.SyncDuration())
		}
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
			g.owner.operations[id] = g.batch.ThreadKey(id)
		}
	}
	for _, release := range g.releases {
		release()
	}
	g.batch = &app.PostingBatch{CommitGroup: g.owner.sharedThreadWAL}
	g.settlers = nil
	g.releases = nil
	g.guards = nil
	g.validations = nil
	g.verifiedCaptures = nil
	g.guardPruning = nil
	g.full = false
}

// needsRebuild は取消・メモリ不足で未保存の操作だけを続行する。確定済み操作は再実行しない。
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
