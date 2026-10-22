// Package board は板ごとの有界・直列実行列を管理する。
package board

import (
	"context"
	"errors"
	"sync"
)

var ErrBusy = errors.New("board queue full")
var ErrClosed = errors.New("board draining")

type result struct {
	Value any
	Err   error
}
type task struct {
	ctx   context.Context
	run   func() (any, error)
	done  chan result
	batch *Batch
	key   uint64
}

// Worker は最大128件の未開始操作を保持する。一度開始した操作は取消しない。
type Worker struct {
	mu       sync.Mutex
	queue    chan task
	closing  chan struct{}
	done     chan struct{}
	closed   bool
	pending  int
	finalize func() error
	finalErr error
}

// NewWorker は板専用の単一実行goroutineを開始する。
func NewWorker() *Worker {
	w := &Worker{queue: make(chan task, 128), closing: make(chan struct{}), done: make(chan struct{})}
	go w.loop()
	return w
}

// Submit は満杯を即時拒否し、開始後はcontext取消でも確定結果まで待つ。
func (w *Worker) Submit(ctx context.Context, run func() (any, error)) (any, error) {
	return w.submit(ctx, run, false, nil, 0)
}

// SubmitIdle は通常要求が実行中・待機中なら保守処理を即時延期する。
// 受付後は通常操作と同じ所有権と終了待ちを維持する。
func (w *Worker) SubmitIdle(ctx context.Context, run func() (any, error)) (any, error) {
	return w.submit(ctx, run, true, nil, 0)
}
func (w *Worker) submit(ctx context.Context, run func() (any, error), idle bool, batch *Batch, key uint64) (any, error) {
	if run == nil {
		return nil, errors.New("nil board operation")
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	t := task{ctx: ctx, run: run, done: make(chan result, 1), batch: batch, key: key}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil, ErrClosed
	}
	if idle && w.pending != 0 {
		w.mu.Unlock()
		return nil, ErrBusy
	}
	if w.pending >= 129 {
		w.mu.Unlock()
		return nil, ErrBusy
	}
	select {
	case w.queue <- t:
		w.pending++
		w.mu.Unlock()
	case <-ctx.Done():
		w.mu.Unlock()
		return nil, ctx.Err()
	default:
		w.mu.Unlock()
		return nil, ErrBusy
	}
	r := <-t.done
	return r.Value, r.Err
}

// Close は未開始操作を拒否し、実行中の保存完了を待つ。
func (w *Worker) Close() {
	_ = w.CloseWithFinalizer(nil)
}

// CloseWithFinalizer は受付を閉じ、実行中の確定と未開始要求の拒否後に所有列で最後の保存を行う。
// 最初のCloseだけがfinalizeを設定し、全呼出しがその確定結果を待つ。
func (w *Worker) CloseWithFinalizer(finalize func() error) error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		w.finalize = finalize
		close(w.closing)
	}
	w.mu.Unlock()
	<-w.done
	return w.finalErr
}
func (w *Worker) loop() {
	defer close(w.done)
	var carry *task
	for {
		if carry != nil {
			t := *carry
			carry = nil
			carry = w.execute(t)
			continue
		}
		select {
		case <-w.closing:
			w.rejectPending()
			if w.finalize != nil {
				w.finalErr = w.finalize()
			}
			return
		case t := <-w.queue:
			carry = w.execute(t)
		}
	}
}
func (w *Worker) rejectPending() {
	for {
		select {
		case t := <-w.queue:
			w.finish(t, result{Err: ErrClosed})
		default:
			return
		}
	}
}

// finish は完了通知より先に受付数を戻し、次の保守判断へ確定状態を見せる。
func (w *Worker) finish(t task, r result) { w.mu.Lock(); w.pending--; w.mu.Unlock(); t.done <- r }
