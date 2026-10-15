// 必須投稿が待機・実行している間、非必須HTTPログの新たな同期を延期する。
package bootstrap

import (
	"context"
	"oimobbs/internal/board"
	"sync"
)

// postingIOPriority は板の有界列を変えず、必須投稿中の非必須保存開始を延期する。
// 開始済みの非必須Syncを投稿が待つ優先度逆転は作らない。
type postingIOPriority struct {
	mu       sync.Mutex
	posts    int
	optional bool
	changed  chan struct{}
}

// submitPosting は板の既存受付上限・取消契約を保ち、列の待機/実行だけをI/O優先対象にする。
// 結果を返す前に優先枠を解放し、後続のサイトmutex取得やHTTP応答へ持ち越さない。
func (r *Repository) submitPosting(ctx context.Context, worker *board.Worker, run func() (any, error)) (any, error) {
	release := r.postingIO.holdPost()
	defer release()
	return worker.Submit(ctx, run)
}

// holdPost は列投入前に投稿を登録する。返した解放はSubmitの終了後に一度呼ぶ。
func (p *postingIOPriority) holdPost() func() {
	p.mu.Lock()
	p.posts++
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		p.posts--
		p.notifyLocked()
		p.mu.Unlock()
	}
}

// beginOptional は投稿列が空のときだけ保存を始める。終了取消で待機を解除する。
// 取得後は返した解放をSync結果確定後に一度呼ぶ。Repository.muを保持して呼ばない。
func (p *postingIOPriority) beginOptional(ctx context.Context) (func(), error) {
	p.mu.Lock()
	for {
		if e := ctx.Err(); e != nil {
			p.mu.Unlock()
			return nil, e
		}
		if p.posts == 0 && !p.optional {
			break
		}
		changed := p.changedLocked()
		p.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		p.mu.Lock()
	}
	p.optional = true
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		p.optional = false
		p.notifyLocked()
		p.mu.Unlock()
	}, nil
}

// changedLocked は状態の次回変更を待つ通知を作る。
func (p *postingIOPriority) changedLocked() <-chan struct{} {
	if p.changed == nil {
		p.changed = make(chan struct{})
	}
	return p.changed
}

// notifyLocked は全待機者に再判定を通知する。
func (p *postingIOPriority) notifyLocked() {
	if p.changed != nil {
		close(p.changed)
		p.changed = nil
	}
}
