// 両出力親・計画親・公開信頼根を固定し、順序付きペア回収を周期実行する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"oimobbs/internal/domain"
)

// BackupPairMaintenanceOptions は正本不要の巡回入力と件数/周期/時間上限。
type BackupPairMaintenanceOptions struct {
	CopyParent    string
	KeysParent    string
	PlanParent    string
	TrustInstance string
	Limit         int
	Interval      time.Duration
	Budget        time.Duration
	Apply         bool
}

// BackupPairMaintenanceReport は一巡回一行の工程結果。秘密や認証エラー詳細は含めない。
type BackupPairMaintenanceReport struct {
	Pass   domain.U64            `json:"pass"`
	Status string                `json:"status"`
	Apply  bool                  `json:"apply"`
	Sweep  BackupPairSweepReport `json:"sweep"`
}

type pairMaintenanceIdentity struct {
	roots    [3][2]domain.U64
	trustSHA domain.Hash
}

func capturePairMaintenanceIdentity(o BackupPairMaintenanceOptions) (v pairMaintenanceIdentity, err error) {
	for i, parent := range []string{o.CopyParent, o.KeysParent, o.PlanParent} {
		d, n, e := replayRootIdentity(parent)
		if e != nil {
			return v, e
		}
		v.roots[i] = [2]domain.U64{d, n}
	}
	_, raw, e := loadBackupTrust(o.TrustInstance)
	if e != nil {
		return v, e
	}
	v.trustSHA = sha256.Sum256(raw)
	return v, nil
}

type backupPairSweepFunc func(context.Context, string, string, string, string, string, int, bool, func() time.Time) (BackupPairSweepReport, error)

// RunBackupPairMaintenance は両出力親.lockを保持し、即時巡回と完了後の周期巡回を行う。
// 3親device/inodeとtrust bytesの差替えを拒否し、新しい子は次の全巡回で扱う。
func RunBackupPairMaintenance(ctx context.Context, o BackupPairMaintenanceOptions, emit func(BackupPairMaintenanceReport) error) error {
	return runBackupPairMaintenance(ctx, o, emit, waitReplayMaintenance, sweepBackupPairs)
}

// runBackupPairMaintenance は待機/巡回を注入できる周期実行部。ページと部分回収の再試行を管理する。
func runBackupPairMaintenance(ctx context.Context, o BackupPairMaintenanceOptions, emit func(BackupPairMaintenanceReport) error, wait func(context.Context, time.Duration) error, sweep backupPairSweepFunc) (err error) {
	if err = validateBackupPairSweep(o.CopyParent, o.KeysParent, o.PlanParent, o.TrustInstance, "", o.Limit); err != nil {
		return err
	}
	if o.Interval < time.Minute || o.Interval > 24*time.Hour || o.Budget < time.Second || o.Budget > 5*time.Minute || emit == nil || wait == nil || sweep == nil {
		return errors.New("pair maintenance requires interval 1m..24h, budget 1s..5m and callbacks")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	identity, err := capturePairMaintenanceIdentity(o)
	if err != nil {
		return err
	}
	unlock, err := lockBackupDirectories(o.CopyParent, o.KeysParent)
	if err != nil {
		return err
	}
	defer func() {
		if e := unlock(); e != nil {
			err = errors.Join(err, e)
		}
	}()
	after := ""
	for pass := domain.U64(1); ; pass++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		current, e := capturePairMaintenanceIdentity(o)
		if e != nil {
			return e
		}
		if current != identity {
			return errors.New("pair maintenance parent or trust changed")
		}
		batch, cancel := context.WithTimeout(ctx, o.Budget)
		result, e := sweep(batch, o.CopyParent, o.KeysParent, o.PlanParent, o.TrustInstance, after, o.Limit, o.Apply, time.Now)
		cancel()
		status := backupMaintenanceStatus(e)
		if err = emit(BackupPairMaintenanceReport{pass, status, o.Apply, result}); err != nil {
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
