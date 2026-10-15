// 証拠照合済み投稿の捕捉境界を停止中バックアップへ渡す。
package app

import (
	"context"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// BackupCapture は所有列が停止中の、完全な投稿正本だけを捕捉する。
func (p *PostingLog) BackupCapture(ctx context.Context) (store.BackupCapture, error) {
	if p.stopped || p.thread == nil {
		return store.BackupCapture{}, ErrEvidenceGap
	}
	return p.thread.BackupCapture(ctx)
}

// PinBackup は証拠欠落のない投稿logを所有処理列内で固定する。
// 返した資源のCopy/Closeは列外で行い、コピー終了または取消時に必ず解放する。
func (p *PostingLog) PinBackup(ctx context.Context, at domain.Time) (*store.PinnedBackup, error) {
	return p.PinBackupLimited(ctx, at, 32<<30)
}

// PinBackupLimited は証拠/期限と参照byte上限を所有列内で確認して固定する。
func (p *PostingLog) PinBackupLimited(ctx context.Context, at domain.Time, maxBytes uint64) (*store.PinnedBackup, error) {
	if p.stopped || p.thread == nil {
		return nil, ErrEvidenceGap
	}
	if p.thread.State().Expires <= at {
		return nil, errors.New("thread expired before backup pin")
	}
	return p.thread.PinBackupLimited(ctx, maxBytes)
}
