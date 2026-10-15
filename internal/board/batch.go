// 待機済みの同種操作だけを取り出し、通常操作の順序を保って一括確定する。
package board

import "context"

// MaxBatchOperations は一括開始する操作数の上限。受付列の128件上限は別途維持する。
const MaxBatchOperations = 64

// BatchOperation は所有列で検査・実行する操作。Runの並列実行は禁止。
// Completeは確定した未保存結果だけを一度先に返す。同じ操作を再実行してはならない。
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
	Run func([]BatchOperation) []BatchResult
	// RunReadyは準備中に到着済みの同種操作を追加収集できる。合計64件、異種操作は追い越さない。
	// collectは所有列上でだけ呼び、RunReady終了後には保持・実行しない。
	RunReady func([]BatchOperation, func() []BatchOperation) []BatchResult
}

// SubmitBatch は同じbatch/keyの連続した待機済み操作をまとめる。収集のために待たない。
// 通常操作や別keyを追い越さず、開始前の取消・終了判定は各Runの直前にも行う。
func (w *Worker) SubmitBatch(ctx context.Context, batch *Batch, key uint64, run func() (any, error)) (any, error) {
	if batch == nil || batch.Run == nil && batch.RunReady == nil {
		return w.Submit(ctx, run)
	}
	return w.submit(ctx, run, false, batch, key)
}

// execute は先頭と同じ一括操作を最大64件集め、異種の次操作を次回へ持ち越す。
func (w *Worker) execute(first task) *task {
	if first.batch == nil {
		v, e := w.invoke(first)
		w.finish(first, result{v, e})
		return nil
	}
	tasks := make([]task, 0, MaxBatchOperations)
	completed := make([]bool, MaxBatchOperations)
	var carry *task
	operation := func(t task) BatchOperation {
		i := len(tasks)
		tasks = append(tasks, t)
		return BatchOperation{Context: t.ctx, Run: func() (any, error) { return w.invoke(t) }, Complete: func(value any, e error) {
			if completed[i] {
				panic("board batch completed twice")
			}
			completed[i] = true
			w.finish(t, result{value, e})
		}}
	}
	collect := func() []BatchOperation {
		var added []BatchOperation
		for carry == nil && len(tasks) < MaxBatchOperations {
			select {
			case t := <-w.queue:
				if t.batch != first.batch || t.key != first.key {
					carry = &t
					return added
				}
				added = append(added, operation(t))
			default:
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
