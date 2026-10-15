// 稼働捕捉の一件排他・投稿/圧縮との容量予約・時間上限付き列外コピーを管理する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
	"path/filepath"
	"sync"
	"time"
)

const onlineBackupDefaultBytes uint64 = 256 << 20
const onlineBackupOverhead uint64 = 16 << 20

// ErrOnlineBackupBusy は同じRepositoryで別の捕捉資源が有効であることを示す。
var ErrOnlineBackupBusy = errors.New("online backup already active")

// ErrOnlineBackupCapacity は捕捉予約を残せる空き容量がないことを示す。
var ErrOnlineBackupCapacity = errors.New("online backup capacity unavailable")

// OnlineBackupCopyOptions は捕捉時参照byte上限と、受付から解放までの協調的な時間上限。
// 零値は256MiB/30s。MaxBytesは1MiB..1GiB、Budgetは1s..5m。
type OnlineBackupCopyOptions struct {
	MaxBytes uint64
	Budget   time.Duration
}

// reserveOnlineBackup は一件分を投稿/圧縮と同じ台帳へ予約する。物理的なdisk確保ではない。
func (r *Repository) reserveOnlineBackup(maxBytes uint64) (func(), error) {
	r.packResourcesMu.Lock()
	defer r.packResourcesMu.Unlock()
	if r.backupActive {
		return nil, ErrOnlineBackupBusy
	}
	probe := r.packSpace
	if probe == nil {
		probe = platform.Space
	}
	space, e := probe(r.cfg.DataDir)
	reserve, re := inspectEmergencyReserve(r.cfg.DataDir)
	bytes := maxBytes + onlineBackupOverhead
	floor := max(uint64(1<<30), space.Total/10)
	held := r.packReserved + r.postReserved + r.backupReserved
	if e != nil || re != nil || reserve.Enabled && !reserve.Ready || space.Available < floor || held > space.Available-floor || bytes > space.Available-floor-held {
		return nil, ErrOnlineBackupCapacity
	}
	r.backupActive = true
	r.backupReserved = bytes
	var once sync.Once
	return func() {
		once.Do(func() {
			r.packResourcesMu.Lock()
			defer r.packResourcesMu.Unlock()
			r.backupActive = false
			r.backupReserved = 0
		})
	}, nil
}

// CopyThreadBackup は時間/参照byte上限内で単一スレッドを捕捉・列外コピーし、必ず解放する。
// 全体バックアップの署名manifest/公開復元は生成しない。失敗した出力は保持する。
func (r *Repository) CopyThreadBackup(ctx context.Context, owner domain.ID, key uint64, target string, o OnlineBackupCopyOptions) (cut store.BackupCapture, err error) {
	if o.MaxBytes == 0 {
		o.MaxBytes = onlineBackupDefaultBytes
	}
	if o.Budget == 0 {
		o.Budget = 30 * time.Second
	}
	if o.MaxBytes < 1<<20 || o.MaxBytes > 1<<30 || o.Budget < time.Second || o.Budget > 5*time.Minute {
		return cut, errors.New("online copy requires bytes 1MiB..1GiB and budget 1s..5m")
	}
	r.mu.Lock()
	e := r.available()
	if e == nil {
		e = r.candidatePath(target)
	}
	r.mu.Unlock()
	if e != nil {
		return cut, e
	}
	batch, cancel := context.WithTimeout(ctx, o.Budget)
	defer cancel()
	pin, e := r.pinThreadBackup(batch, owner, key, o.MaxBytes, o.Budget)
	if e != nil {
		return cut, e
	}
	defer func() {
		err = errors.Join(err, pin.Close())
		if err != nil {
			cut = store.BackupCapture{}
		}
	}()
	if e = backupCapacity(r.cfg.DataDir, filepath.Dir(target), o.MaxBytes+onlineBackupOverhead); e != nil {
		return cut, e
	}
	cut, err = pin.Copy(batch, target)
	if e := batch.Err(); e != nil {
		err = errors.Join(e, err)
	}
	if err == nil && cut.Expires != 0 && time.Now().UnixNano() >= int64(cut.Expires) {
		err = errors.New("thread expired during online copy")
	}
	return cut, err
}
