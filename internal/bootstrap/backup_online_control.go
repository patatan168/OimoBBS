// サイト制御と板一括コピーを、既存の稼働捕捉予約・期限・出力保護へ接続する。
package bootstrap

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// PinSiteBackup はRepositoryの管理排他内でサイト制御だけを固定し、列外コピーへ渡す。
// 全体枠と容量予約はthread/boardと共通。監査/job/metadataや板との全体整合性は含まない。
func (r *Repository) PinSiteBackup(ctx context.Context, options OnlineBackupCopyOptions) (*store.PinnedBackup, error) {
	o, e := normalizeOnlineGroupOptions(OnlineBackupGroupOptions{MaxBytes: options.MaxBytes, Budget: options.Budget, MaxOwners: 1})
	if e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	lifetime := newOnlineBackupLifetime(ctx, o.Budget)
	life, cancel := lifetime.Context, lifetime.cancel
	release, e := r.reserveOnlineBackup(o.MaxBytes)
	if e != nil {
		cancel()
		return nil, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e = r.available()
	var pin *store.PinnedBackup
	if e == nil {
		pin, e = r.site.PinBackupLimited(life, o.MaxBytes)
	}
	if e == nil {
		e = pin.Manage(life, func() { cancel(); release() })
	}
	if e != nil {
		if pin != nil {
			e = errors.Join(e, pin.Close())
		}
		cancel()
		release()
		return nil, e
	}
	return pin, nil
}

// preflightOnlineTarget は元データ領域外の新規private出力を、捕捉の前に確認する。
func (r *Repository) preflightOnlineTarget(target string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	return r.candidatePath(target)
}

// CopyBoardBackup は板の一括固定・列外コピー・全解放を一工程にする。途中出力は保持する。
func (r *Repository) CopyBoardBackup(ctx context.Context, owner domain.ID, target string, options OnlineBackupGroupOptions) (OnlineBackupGroupCapture, error) {
	if e := r.preflightOnlineTarget(target); e != nil {
		return OnlineBackupGroupCapture{}, e
	}
	group, e := r.PinBoardBackup(ctx, owner, options)
	if e != nil {
		return OnlineBackupGroupCapture{}, e
	}
	return group.Copy(ctx, target)
}

// CopySiteBackup はサイト制御の管理付き部品コピー。完成manifestや鍵束は生成しない。
func (r *Repository) CopySiteBackup(ctx context.Context, target string, options OnlineBackupCopyOptions) (cut store.BackupCapture, err error) {
	if e := r.preflightOnlineTarget(target); e != nil {
		return cut, e
	}
	pin, e := r.PinSiteBackup(ctx, options)
	if e != nil {
		return cut, e
	}
	defer func() {
		err = errors.Join(err, pin.Close())
		if err != nil {
			cut = store.BackupCapture{}
		}
	}()
	if e = backupCapacity(r.cfg.DataDir, filepath.Dir(target), pin.ReferenceBytes()+onlineBackupOverhead); e != nil {
		return cut, e
	}
	return pin.Copy(ctx, target)
}

// onlineBackupLifetime はCloseまで残すcontextの取消所有権を表す。
type onlineBackupLifetime struct {
	context.Context
	cancel context.CancelFunc
}

// newOnlineBackupLifetime は期限と取消をまとめて返し、捕捉資源への所有権移譲を明示する。
func newOnlineBackupLifetime(ctx context.Context, budget time.Duration) onlineBackupLifetime {
	life, cancel := context.WithTimeout(ctx, budget)
	return onlineBackupLifetime{Context: life, cancel: cancel}
}
