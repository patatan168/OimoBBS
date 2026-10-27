// 一括操作の順序境界、収集待ちなし、取消と受付数の上限を検査する。
package board

import (
	"context"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func waitPending(t *testing.T, w *Worker, n int) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for {
		w.mu.Lock()
		pending := w.pending
		w.mu.Unlock()
		if pending == n {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("pending=%d want=%d", pending, n)
		}
		runtime.Gosched()
	}
}

func TestBatchOrderAndCancellation(t *testing.T) {
	w := NewWorker()
	defer w.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 8)
	go func() {
		_, e := w.Submit(context.Background(), func() (any, error) { close(entered); <-release; return nil, nil })
		done <- e
	}()
	<-entered
	var order []int
	var sizes []int
	batch := &Batch{Run: func(ops []BatchOperation) []BatchResult {
		sizes = append(sizes, len(ops))
		out := make([]BatchResult, len(ops))
		for i, op := range ops {
			out[i].Value, out[i].Err = op.Run()
		}
		return out
	}}
	for i := 1; i <= 5; i++ {
		i := i
		ctx := context.Background()
		if i == 2 {
			c, cancel := context.WithCancel(ctx)
			cancel()
			ctx = c
		}
		go func() {
			var e error
			run := func() (any, error) { order = append(order, i); return i, nil }
			if i == 3 {
				_, e = w.Submit(ctx, run)
			} else {
				_, e = w.SubmitBatch(ctx, batch, 7, run)
			}
			done <- e
		}()
		if i == 2 {
			if e := <-done; e != context.Canceled {
				t.Fatal(e)
			}
		} else {
			n := i + 1
			if i > 2 {
				n--
			}
			waitPending(t, w, n)
		}
	}
	close(release)
	for range 5 {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	if !reflect.DeepEqual(order, []int{1, 3, 4, 5}) || !reflect.DeepEqual(sizes, []int{1, 2}) {
		t.Fatal(order, sizes)
	}
}

func TestBatchConfirmationDoesNotWaitForCommit(t *testing.T) {
	w := NewWorker()
	defer w.Close()
	blocked, unblock := make(chan struct{}), make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, e := w.Submit(context.Background(), func() (any, error) { close(blocked); <-unblock; return nil, nil })
		firstDone <- e
	}()
	<-blocked
	batch := &Batch{Run: func(ops []BatchOperation) []BatchResult {
		out := make([]BatchResult, len(ops))
		for i, op := range ops {
			out[i].Value, out[i].Err = op.Run()
			if out[i].Value == "confirmation" {
				op.Complete(out[i].Value, out[i].Err)
			}
		}
		return out
	}}
	confirmed := make(chan BatchResult, 1)
	go func() {
		v, e := w.SubmitBatch(context.Background(), batch, 7, func() (any, error) { return "confirmation", nil })
		confirmed <- BatchResult{v, e}
	}()
	waitPending(t, w, 2)
	storing, releaseStore := make(chan struct{}), make(chan struct{})
	stored := make(chan error, 1)
	go func() {
		_, e := w.SubmitBatch(context.Background(), batch, 7, func() (any, error) { close(storing); <-releaseStore; return "stored", nil })
		stored <- e
	}()
	waitPending(t, w, 3)
	close(unblock)
	<-storing
	select {
	case r := <-confirmed:
		if r.Value != "confirmation" || r.Err != nil {
			t.Error(r)
		}
	case <-time.After(5 * time.Second):
		t.Error("confirmation waited for storage")
	}
	w.mu.Lock()
	pending := w.pending
	w.mu.Unlock()
	if pending != 1 {
		t.Error("confirmation reservation not released", pending)
	}
	close(releaseStore)
	if e := <-stored; e != nil {
		t.Error(e)
	}
	if e := <-firstDone; e != nil {
		t.Error(e)
	}
}

func TestBatchReadyFollowUpAndOrderBarrier(t *testing.T) {
	w := NewWorker()
	defer w.Close()
	prepared, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var order, sizes []int
	batch := &Batch{RunReady: func(ops []BatchOperation, collect func() []BatchOperation) []BatchResult {
		var out []BatchResult
		for i := 0; i < len(ops); i++ {
			v, e := ops[i].Run()
			out = append(out, BatchResult{v, e})
			if v == 1 {
				ops[i].Complete(v, e)
				close(prepared)
				<-release
			}
			if i == len(ops)-1 {
				ops = append(ops, collect()...)
			}
		}
		sizes = append(sizes, len(ops))
		return out
	}}
	done := make(chan error, 4)
	for i := 1; i <= 4; i++ {
		i := i
		go func() {
			run := func() (any, error) { order = append(order, i); return i, nil }
			var e error
			if i == 3 {
				_, e = w.Submit(context.Background(), run)
			} else {
				_, e = w.SubmitBatch(context.Background(), batch, 7, run)
			}
			done <- e
		}()
		if i == 1 {
			<-prepared
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		} else {
			waitPending(t, w, i-1)
		}
	}
	close(release)
	for range 3 {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	if !reflect.DeepEqual(order, []int{1, 2, 3, 4}) || !reflect.DeepEqual(sizes, []int{2, 1}) {
		t.Fatal(order, sizes)
	}
}

func TestBatchReadyCollectLimit(t *testing.T) {
	w := NewWorker()
	defer w.Close()
	prepared, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var sizes []int
	batch := &Batch{RunReady: func(ops []BatchOperation, collect func() []BatchOperation) []BatchResult {
		if len(sizes) == 0 {
			close(prepared)
			<-release
		}
		ops = append(ops, collect()...)
		if more := collect(); len(more) != 0 {
			t.Error("collection exceeded total limit", len(more))
		}
		out := make([]BatchResult, len(ops))
		for i, op := range ops {
			out[i].Value, out[i].Err = op.Run()
		}
		sizes = append(sizes, len(ops))
		return out
	}}
	done := make(chan error, MaxBatchOperations+5)
	for i := 0; i < MaxBatchOperations+5; i++ {
		go func() {
			_, e := w.SubmitBatch(context.Background(), batch, 7, func() (any, error) { return "saved", nil })
			done <- e
		}()
		if i == 0 {
			<-prepared
		}
		waitPending(t, w, i+1)
	}
	close(release)
	for range MaxBatchOperations + 5 {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	if !reflect.DeepEqual(sizes, []int{MaxBatchOperations, 5}) {
		t.Fatal(sizes)
	}
}

// 確認操作は先に返し、保存候補64件の予算内でのみ論理操作枠を拡張する。
func TestBatchReadyBudgetCountsPendingStorage(t *testing.T) {
	t.Run("storage_and_confirmation", func(t *testing.T) { testBatchReadyBudget(t, true) })
	t.Run("confirmation_only", func(t *testing.T) { testBatchReadyBudget(t, false) })
}

func testBatchReadyBudget(t *testing.T, mixed bool) {
	t.Helper()
	w := NewWorker()
	defer w.Close()
	started, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	running, stored, confirmed := false, 0, 0
	var sizes, saved []int
	batch := &Batch{CollectLimit: 2 * MaxBatchOperations, CollectBudget: func() int {
		if !running {
			return MaxBatchOperations - 1
		}
		return min(MaxBatchOperations-stored, MaxBatchOperations-confirmed)
	}}
	batch.RunReady = func(ops []BatchOperation, collect func() []BatchOperation) []BatchResult {
		if len(sizes) == 0 {
			close(started)
			<-release
		}
		running, stored, confirmed = true, 0, 0
		var results []BatchResult
		for i := 0; i < len(ops); i++ {
			value, err := ops[i].Run()
			results = append(results, BatchResult{Value: value, Err: err})
			if value.(bool) {
				stored++
				if stored > MaxBatchOperations {
					t.Error("exceeded durable storage group", stored)
				}
			} else {
				confirmed++
				if confirmed > MaxBatchOperations {
					t.Error("retained too many completed confirmations", confirmed)
				}
				ops[i].Complete(value, err)
			}
			if i == len(ops)-1 {
				ops = append(ops, collect()...)
			}
		}
		sizes, saved = append(sizes, len(ops)), append(saved, stored)
		return results
	}
	done := make(chan error, 129)
	for i := range 129 {
		go func() {
			_, err := w.SubmitBatch(t.Context(), batch, 7, func() (any, error) { return mixed && i%2 == 1, nil })
			done <- err
		}()
		if i == 0 {
			<-started
		}
		waitPending(t, w, i+1)
	}
	if _, err := w.SubmitBatch(t.Context(), batch, 7, func() (any, error) { return false, nil }); err != ErrBusy {
		t.Fatal("changed admission bound", err)
	}
	close(release)
	for range 129 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	wantSizes, wantSaved := []int{64, 64, 1}, []int{0, 0, 0}
	if mixed {
		// 次の操作種別は未実行なので、確認枠64件に達した時点で保守的に区切る。
		wantSizes, wantSaved = []int{127, 2}, []int{63, 1}
	}
	if !reflect.DeepEqual(sizes, wantSizes) || !reflect.DeepEqual(saved, wantSaved) {
		t.Fatal("storage/confirmation grouping", sizes, saved)
	}
}
