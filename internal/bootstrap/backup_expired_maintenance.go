// 本文コピーの専用親を排他保持し、別保管鍵による期限巡回を独立して周期実行する。
package bootstrap

import (
	"context"
	"errors"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
)

// BackupMaintenanceOptions は本文と鍵束の親、巡回上限と完了後の待機時間。
type BackupMaintenanceOptions struct {
	CopyParent string
	KeysParent string
	Limit      int
	Interval   time.Duration
	Budget     time.Duration
	Apply      bool
}

// BackupMaintenanceReport は一回の本文/鍵束期限巡回結果。秘密や認証エラー詳細を含めない。
type BackupMaintenanceReport struct {
	Pass   domain.U64        `json:"pass"`
	Status string            `json:"status"`
	Apply  bool              `json:"apply"`
	Sweep  BackupSweepReport `json:"sweep"`
}

func (o BackupMaintenanceOptions) validate() error {
	if o.Limit < 1 || o.Limit > 128 || o.Interval < time.Minute || o.Interval > 24*time.Hour || o.Budget < time.Second || o.Budget > 5*time.Minute {
		return errors.New("backup maintenance requires limit 1..128, interval 1m..24h and budget 1s..5m")
	}
	return separateBackupPaths(o.CopyParent, o.KeysParent)
}

// RunBackupMaintenance は即時一回、以後完了からinterval待って本文期限巡回を行う。
// 本文親.lockの非待機排他で二重起動を拒否し、本文/鍵束親のdevice/inodeを毎回照合する。
// 新しい子は次の全巡回で扱い、各組の鍵束は毎回認証する。正本設定や公開listenerは不要。
// emitは逐次呼び出す。遅い出力先の書込みをcontextで強制中断する契約ではない。
func RunBackupMaintenance(ctx context.Context, o BackupMaintenanceOptions, emit func(BackupMaintenanceReport) error) error {
	return runBackupMaintenance(ctx, o, emit, waitReplayMaintenance, SweepExpiredBackups)
}

// runBackupMaintenance は待機/巡回を注入し、周期と中断を実時間待機なしで検証できる。
func runBackupMaintenance(ctx context.Context, o BackupMaintenanceOptions, emit func(BackupMaintenanceReport) error, wait func(context.Context, time.Duration) error, sweep func(context.Context, string, string, string, int, bool) (BackupSweepReport, error)) (err error) {
	if err = o.validate(); err != nil {
		return err
	}
	if emit == nil {
		return errors.New("backup maintenance requires a report writer")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	identity, err := captureBackupMaintenanceIdentity(o)
	if err != nil {
		return err
	}
	lock, err := platform.Lock(o.CopyParent)
	if err != nil {
		return err
	}
	defer func() {
		if e := platform.Unlock(lock); e != nil {
			err = errors.Join(err, e)
		}
	}()
	after := ""
	for pass := domain.U64(1); ; pass++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = identity.check(o); err != nil {
			return err
		}
		batch, cancel := context.WithTimeout(ctx, o.Budget)
		result, e := sweep(batch, o.CopyParent, o.KeysParent, after, o.Limit, o.Apply)
		cancel()
		status := backupMaintenanceStatus(e)
		if err = emit(BackupMaintenanceReport{pass, status, o.Apply, result}); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if status == "failed" || status == "interrupted" {
			return e
		}
		after = ""
		if result.More {
			after = result.Next
		}
		if err = wait(ctx, o.Interval); err != nil {
			return err
		}
	}
}

type backupMaintenanceIdentity struct {
	copyDevice, copyInode domain.U64
	keysDevice, keysInode domain.U64
}

// captureBackupMaintenanceIdentity は所有者限定の両親を検査し、別用途への差替えを検知する。
func captureBackupMaintenanceIdentity(o BackupMaintenanceOptions) (backupMaintenanceIdentity, error) {
	dev, inode, e := replayRootIdentity(o.CopyParent)
	if e != nil {
		return backupMaintenanceIdentity{}, e
	}
	keysDev, keysInode, e := replayRootIdentity(o.KeysParent)
	if e != nil {
		return backupMaintenanceIdentity{}, e
	}
	return backupMaintenanceIdentity{dev, inode, keysDev, keysInode}, nil
}

func (v backupMaintenanceIdentity) check(o BackupMaintenanceOptions) error {
	next, e := captureBackupMaintenanceIdentity(o)
	if e != nil {
		return e
	}
	if next != v {
		return errors.New("backup maintenance copy or key parent changed")
	}
	return nil
}

func backupMaintenanceStatus(err error) string {
	switch {
	case err == nil:
		return "completed"
	case errors.Is(err, ErrBackupSweepRejected):
		return "needs_attention"
	case errors.Is(err, context.DeadlineExceeded):
		return "budget_exhausted"
	case errors.Is(err, context.Canceled):
		return "interrupted"
	default:
		return "failed"
	}
}
