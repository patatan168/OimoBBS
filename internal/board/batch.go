// 待機済みの同種操作だけを取り出し、通常操作の順序を保って一括確定する。
package board

import (
	"context"
	"time"
)

// MaxBatchOperations は既定の一括開始件数。受付数・受付列の上限は別途維持する。
const MaxBatchOperations = 64

// BatchOperation は所有列で検査・実行する操作。Runの並列実行は禁止。
// Completeは確定した未保存結果、または保存処理を完了した結果を一度先に返す。
// 通知済みの操作を再実行してはならない。
type BatchOperation struct {
	Context  context.Context
	Run      func() (any, error)
	Complete func(any, error)
}

// BatchResult は一括保存の結果を元の投入順へ返すための内部結果。
type BatchResult struct {
	Value any
	Err   error
}

// Batch は所有列上で準備と一括確定を行う。入力と同数の結果を返す。
type Batch struct {
	// AcrossKeysは同じ所有者の異なるkeyを順序通り検証し、共有同期できるbatchだけが有効化する。
	AcrossKeys bool
	// CollectWindowは保存候補を持つ場合の累積収集待ち上限。零は即時収集。
	CollectWindow time.Duration
	// CollectLimitは確認等を含む操作数の上限。零は64、指定時も受付列の容量まで。
	// 保存候補数は別途CollectBudgetで制限する。
	CollectLimit int
	// CollectBudgetは追加収集できる操作数を所有列上で返す。nilは残りのCollectLimitまで。
	// 同種操作を実行した後に再評価し、未実行の追加分は保守的に全て保存候補として数える。
	CollectBudget func() int
	// CanWaitは所有列内でだけ呼ぶ。確認だけの群では待機を許可しない。
	CanWait func() bool
	Run     func([]BatchOperation) []BatchResult
	// RunReadyは準備中に到着済みの同種操作を追加収集できる。異種操作は追い越さない。
	// collectは所有列上でだけ呼び、RunReady終了後には保持・実行しない。
	RunReady func([]BatchOperation, func() []BatchOperation) []BatchResult
}

// SubmitBatch は同じbatchの連続した待機済み操作をまとめる。既定では収集のために待たない。
// 通常操作を追い越さず、既定では別keyでも区切る。開始前の取消・終了判定は各Runの直前に行う。
func (w *Worker) SubmitBatch(ctx context.Context, batch *Batch, key uint64, run func() (any, error)) (any, error) {
	if batch == nil || batch.Run == nil && batch.RunReady == nil {
		return w.Submit(ctx, run)
	}
	return w.submit(ctx, run, false, batch, key)
}

// execute は先頭と同じ操作を収集上限・予算内で集め、異種の次操作を次回へ持ち越す。
func (w *Worker) execute(first task) *task {
	if first.batch == nil {
		v, e := w.invoke(first)
		w.finish(first, result{v, e})
		return nil
	}
	limit := first.batch.CollectLimit
	if limit <= 0 {
		limit = MaxBatchOperations
	}
	limit = max(1, min(limit, cap(w.queue)))
	tasks := make([]task, 0, limit)
	completed := make([]bool, limit)
	var carry *task
	remaining := first.batch.CollectWindow
	take := func() (task, bool, bool) {
		select {
		case t := <-w.queue:
			return t, true, false
		default:
		}
		if remaining <= 0 || first.batch.CanWait == nil || !first.batch.CanWait() {
			return task{}, false, false
		}
		start := time.Now()
		timer := time.NewTimer(remaining)
		defer func() { remaining -= time.Since(start); timer.Stop() }()
		select {
		case t := <-w.queue:
			return t, true, true
		case <-timer.C:
			return task{}, false, true
		case <-w.closing:
			return task{}, false, true
		}
	}
	operation := func(t task) BatchOperation {
		i := len(tasks)
		tasks = append(tasks, t)
		return BatchOperation{Context: t.ctx, Run: func() (any, error) { return w.invoke(t) }, Complete: func(value any, e error) {
			if completed[i] {
				panic("board batch completed twice")
			}
			completed[i] = true
			w.finish(t, result{value, e})
			// 先に返した確認操作の入力を、残りの保存待ちの間まで保持しない。
			t = task{}
			tasks[i] = task{}
		}}
	}
	collect := func() []BatchOperation {
		var added []BatchOperation
		remaining := limit - len(tasks)
		if first.batch.CollectBudget != nil {
			remaining = min(remaining, max(0, first.batch.CollectBudget()))
		}
		for carry == nil && len(added) < remaining {
			t, ok, waited := take()
			if !ok {
				return added
			}
			if t.batch != first.batch || !first.batch.AcrossKeys && t.key != first.key {
				carry = &t
				return added
			}
			added = append(added, operation(t))
			// 新着操作を直ちに実行し、未保存の確認結果を次の往復へ返す。
			if waited {
				return added
			}
		}
		return added
	}
	ops := []BatchOperation{operation(first)}
	ops = append(ops, collect()...)
	var results []BatchResult
	if first.batch.RunReady != nil {
		results = first.batch.RunReady(ops, collect)
	} else {
		results = first.batch.Run(ops)
	}
	if len(results) != len(tasks) {
		panic("board batch result count mismatch")
	}
	for i, t := range tasks {
		if !completed[i] {
			w.finish(t, result{results[i].Value, results[i].Err})
		}
	}
	return carry
}

// invoke は開始前だけ取消/受付終了を確認し、開始した処理の確定を待つ。
func (w *Worker) invoke(t task) (any, error) {
	w.mu.Lock()
	closed := w.closed
	w.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	if e := t.ctx.Err(); e != nil {
		return nil, e
	}
	return t.run()
}
