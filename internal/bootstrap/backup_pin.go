// 稼働板ワーカーの空き時間に投稿の確定境界を固定し、列外コピーへ渡す。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"time"
)

// PinThreadBackup は稼働Repositoryの証拠照合済みスレッドを所有列内で固定する。
// Repository全体で一件・参照256MiB・保持30秒まで。取消/期限切れでは自動解放する。
// 板が実行中/待機中なら即時延期し、返した資源は列外のCopy/Closeで早期解放する。
// 単一スレッドの部品捕捉であり、site全体の完成バックアップ/公開復元ではない。
func (r *Repository) PinThreadBackup(ctx context.Context, owner domain.ID, key uint64) (*store.PinnedBackup, error) {
	return r.pinThreadBackup(ctx, owner, key, onlineBackupDefaultBytes, 30*time.Second)
}

// pinThreadBackup は全体予約と保持期限を受付前に確保し、全終了経路へ解放を接続する。
func (r *Repository) pinThreadBackup(ctx context.Context, owner domain.ID, key uint64, maxBytes uint64, budget time.Duration) (*store.PinnedBackup, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	r.mu.Lock()
	if e := r.available(); e != nil {
		r.mu.Unlock()
		return nil, e
	}
	b := r.posting[owner]
	r.mu.Unlock()
	if b == nil {
		return nil, errors.New("posting board not found")
	}
	lifetime, cancel := context.WithTimeout(ctx, budget)
	release, e := r.reserveOnlineBackup(maxBytes)
	if e != nil {
		cancel()
		return nil, e
	}
	value, e := b.worker.SubmitIdle(lifetime, func() (any, error) {
		if b.stopped || b.threads[key] == nil {
			return nil, ErrPostingUnavailable
		}
		pin, e := b.threads[key].PinBackupLimited(lifetime, domain.Time(b.clock().UnixNano()), maxBytes)
		if e != nil {
			return nil, e
		}
		if e = pin.Manage(lifetime, func() { cancel(); release() }); e != nil {
			_ = pin.Close()
			return nil, e
		}
		return pin, nil
	})
	if e != nil {
		cancel()
		release()
		return nil, e
	}
	return value.(*store.PinnedBackup), nil
}
