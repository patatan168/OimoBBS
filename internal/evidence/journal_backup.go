// 署名連鎖の照合済みjournalを、停止中バックアップの確定prefixへ束縛する。
package evidence

import (
	"context"
	"errors"
	"oimobbs/internal/store"
)

// BackupCapture は作成済み・照合済みjournalだけをコピー対象にする。
func (j *Journal) BackupCapture(ctx context.Context) (store.BackupCapture, error) {
	if j.stopped || j.log == nil {
		return store.BackupCapture{}, errors.New("journal is not available for backup")
	}
	cut, e := j.log.BackupCapture(ctx)
	if e == nil {
		cut.Expires = j.retention
	}
	return cut, e
}

// PinBackup は照合済みjournalの確定境界を所有処理列内で固定する。
// payloadコピーは列外で行える。Copy/Closeで資源を必ず解放する。
func (j *Journal) PinBackup(ctx context.Context) (*store.PinnedBackup, error) {
	return j.PinBackupLimited(ctx, 32<<30)
}

// PinBackupLimited は所有処理列で証拠WAL/snapshotの参照量を制限して固定する。
func (j *Journal) PinBackupLimited(ctx context.Context, maxBytes uint64) (*store.PinnedBackup, error) {
	if j.stopped || j.log == nil {
		return nil, errors.New("journal is not available for backup")
	}
	pin, e := j.log.PinBackupLimited(ctx, maxBytes)
	if e == nil {
		if e = pin.LimitExpiry(j.retention); e != nil {
			return nil, errors.Join(e, pin.Close())
		}
	}
	return pin, e
}

// HasPersistedLog は所有処理列内で保存済みjournalの有無を返す。未投稿の日を捕捉から除く。
func (j *Journal) HasPersistedLog() bool { return j.log != nil }
