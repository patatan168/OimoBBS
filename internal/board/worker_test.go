// 並列投入・取消・終了の操作順をタイマーなしで検査する。
package board

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestSerial(t *testing.T) {
	w := NewWorker()
	defer w.Close()
	n := 0
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			_, e := w.Submit(context.Background(), func() (any, error) { n++; return n, nil })
			if e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	if n != 100 {
		t.Fatal(n)
	}
}

func TestFinalSaveFollowsStartedCommit(t *testing.T) {
	w := NewWorker()
	entered, release := make(chan struct{}), make(chan struct{})
	posted := make(chan error, 1)
	order := []string{}
	go func() {
		_, e := w.Submit(context.Background(), func() (any, error) { close(entered); <-release; order = append(order, "committed"); return nil, nil })
		posted <- e
	}()
	<-entered
	failure := errors.New("final save failed")
	closed := make(chan error, 1)
	go func() {
		closed <- w.CloseWithFinalizer(func() error { order = append(order, "final"); return failure })
	}()
	<-w.closing
	if _, e := w.Submit(context.Background(), func() (any, error) { return nil, nil }); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
	close(release)
	if e := <-posted; e != nil {
		t.Fatal(e)
	}
	if e := <-closed; e != failure {
		t.Fatal("lost final result", e)
	}
	if !reflect.DeepEqual(order, []string{"committed", "final"}) {
		t.Fatal(order)
	}
	if e := w.CloseWithFinalizer(func() error { t.Error("final save repeated"); return nil }); e != failure {
		t.Fatal(e)
	}
}
func TestCancellationAfterStart(t *testing.T) {
	w := NewWorker()
	ctx, cancel := context.WithCancel(context.Background())
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		v, e := w.Submit(ctx, func() (any, error) { close(started); <-release; return "committed", nil })
		if e == nil && v != "committed" {
			t.Error(v)
		}
		done <- e
	}()
	<-started
	cancel()
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	w.Close()
	if _, e := w.Submit(context.Background(), func() (any, error) { t.Fatal("ran after close"); return nil, nil }); e != ErrClosed {
		t.Fatal(e)
	}
}

// TestMaintenanceAdmission は投稿実行中の保守延期と完了後の再開を確認する。
func TestMaintenanceAdmission(t *testing.T) {
	w := NewWorker()
	defer w.Close()
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := w.Submit(context.Background(), func() (any, error) { close(started); <-release; return nil, nil })
		done <- e
	}()
	<-started
	_, e := w.SubmitIdle(context.Background(), func() (any, error) { t.Error("maintenance ran during posting"); return nil, nil })
	close(release)
	if postErr := <-done; postErr != nil {
		t.Fatal(postErr)
	}
	if e != ErrBusy {
		t.Fatal(e)
	}
	v, e := w.SubmitIdle(context.Background(), func() (any, error) { return "maintenance", nil })
	if e != nil || v != "maintenance" {
		t.Fatal(v, e)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = w.SubmitIdle(canceled, func() (any, error) { return nil, nil }); e != context.Canceled {
		t.Fatal(e)
	}
}
