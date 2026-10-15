// 鍵親・計画親・公開信頼根を固定し、署名計画による回収を独立して周期実行する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

// BackupKeysMaintenanceOptions は署名計画巡回の入力と上限。正本設定は不要。
type BackupKeysMaintenanceOptions struct {
	KeysParent    string
	PlanParent    string
	TrustInstance string
	Limit         int
	Interval      time.Duration
	Budget        time.Duration
	Apply         bool
}

// RunBackupKeysMaintenance は即時巡回後、完了からinterval待機する。
// 鍵親.lockと両親のdevice/inode固定は本文巡回と共通の実行部品を使う。
// 信頼根のbytesを毎回照合し、各計画は毎回署名認証する。計画追加/使用済み化は許す。
func RunBackupKeysMaintenance(ctx context.Context, o BackupKeysMaintenanceOptions, emit func(BackupMaintenanceReport) error) error {
	return runBackupKeysMaintenance(ctx, o, emit, waitReplayMaintenance, sweepPlannedBackupKeys)
}

// runBackupKeysMaintenance は待機と時計付き巡回を注入できる周期実行部。
func runBackupKeysMaintenance(ctx context.Context, o BackupKeysMaintenanceOptions, emit func(BackupMaintenanceReport) error, wait func(context.Context, time.Duration) error, sweep func(context.Context, string, string, string, string, int, bool, func() time.Time) (BackupSweepReport, error)) error {
	if e := validatePlannedKeysSweep(o.KeysParent, o.PlanParent, o.TrustInstance, "", o.Limit); e != nil {
		return e
	}
	_, raw, e := loadBackupTrust(o.TrustInstance)
	if e != nil {
		return e
	}
	trustSHA := sha256.Sum256(raw)
	base := BackupMaintenanceOptions{o.KeysParent, o.PlanParent, o.Limit, o.Interval, o.Budget, o.Apply}
	return runBackupMaintenance(ctx, base, emit, wait, func(ctx context.Context, keys, plans, after string, limit int, apply bool) (BackupSweepReport, error) {
		_, current, e := loadBackupTrust(o.TrustInstance)
		if e != nil {
			return BackupSweepReport{Items: []BackupSweepItem{}}, e
		}
		if sha256.Sum256(current) != trustSHA {
			return BackupSweepReport{Items: []BackupSweepItem{}}, errors.New("backup key maintenance trust changed")
		}
		return sweep(ctx, keys, plans, o.TrustInstance, after, limit, apply, time.Now)
	})
}
