// 必須投稿の待機中に非必須Syncが追い越さず、取消・完了後に再開することを検査する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/board"
	"runtime"
	"testing"
	"time"
)

func TestPostingIOPriority(t *testing.T) {
	var p postingIOPriority
	finishOptional, err := p.beginOptional(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	finishPost := p.holdPost()
	finishOptional()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.beginOptional(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	finishPost()
	release, err := p.beginOptional(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	if p.posts != 0 || p.optional {
		t.Fatal("I/O枠を解放しなかった")
	}
}

func TestPostingIOPriorityKeepsAllBoardsAhead(t *testing.T) {
	var p postingIOPriority
	first, second := p.holdPost(), p.holdPost()
	first()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		release, err := p.beginOptional(ctx)
		if release != nil {
			release()
		}
		result <- err
	}()
	waitForIOWaiter(t, &p)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal("他の板の投稿を追い越した", err)
	}
	second()
	release, err := p.beginOptional(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestSubmitPostingDoesNotWaitForStartedOptionalSync(t *testing.T) {
	r := &Repository{}
	worker := board.NewWorker()
	defer worker.Close()
	finishOptional, err := r.postingIO.beginOptional(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, err := r.submitPosting(context.Background(), worker, func() (any, error) { close(started); return nil, nil })
		if err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Error("必須投稿が開始済みの非必須Syncを待つ優先度逆転")
	}
	finishOptional()
	<-done
	if r.postingIO.posts != 0 {
		t.Fatal("投稿の優先枠が残った")
	}
}

func TestSubmitPostingReleasesPriorityOnRejectedSubmission(t *testing.T) {
	r := &Repository{}
	worker := board.NewWorker()
	worker.Close()
	if _, err := r.submitPosting(context.Background(), worker, func() (any, error) { t.Error("終了済みworkerで実行した"); return nil, nil }); !errors.Is(err, board.ErrClosed) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.submitPosting(ctx, worker, func() (any, error) { return nil, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if r.postingIO.posts != 0 {
		t.Fatal("拒否/取消で優先枠が残った")
	}
}

// waitForIOWaiter は実際の待機登録を確認し、goroutine起動の速さに依存した誤合格を防ぐ。
func waitForIOWaiter(t *testing.T, p *postingIOPriority) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		waiting := p.changed != nil
		p.mu.Unlock()
		if waiting {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("I/O待機が登録されなかった")
}
