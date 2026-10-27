// 通常は必須投稿を優先し、有界の非必須列が逼迫したときだけ保存の飢餓を防ぐ。
package bootstrap

import (
	"context"
	"oimobbs/internal/board"
	"sync"
)

// postingIOPriority は板の有界列を変えず、通常の非必須保存開始を必須投稿より後へ回す。
// 開始済みの非必須Syncを投稿が待つ優先度逆転は作らない。
type postingIOPriority struct {
	mu       sync.Mutex
	posts    int
	optional bool
	changed  chan struct{}
}

// hasPosts は既に受付列へ入った投稿の進行枠を残す判断に使う。
func (p *postingIOPriority) hasPosts() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.posts > 0
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
	return p.beginOptionalWithPressure(ctx, nil, nil)
}

// beginOptionalWithPressure は通常は投稿を優先し、有界列の逼迫時だけ一つの非必須batchを並行保存する。
// 投稿は開始済みの非必須保存を待たない。pressureは非ブロッキングの状態参照で、wakeは逼迫通知。
func (p *postingIOPriority) beginOptionalWithPressure(ctx context.Context, pressure func() bool, wake <-chan struct{}) (func(), error) {
	p.mu.Lock()
	for {
		if e := ctx.Err(); e != nil {
			p.mu.Unlock()
			return nil, e
		}
		if !p.optional && (p.posts == 0 || pressure != nil && pressure()) {
			break
		}
		changed := p.changedLocked()
		p.mu.Unlock()
		select {
		case <-changed:
		case <-wake:
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
