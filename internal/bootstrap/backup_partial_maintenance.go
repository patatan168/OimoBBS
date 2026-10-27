// 用途別の未完成出力を外部署名計画で有界巡回し、共有排他で周期回収する。
package bootstrap

import (
	"context"
	"errors"
	"time"

	"oimobbs/internal/platform"
)

// BackupPartialMaintenanceOptions は本文/鍵束のどちらか一方を扱う巡回入力。
// Kindはbody/keys、親は最終配置、計画はPlanParent/name.json。正本設定は不要。
type BackupPartialMaintenanceOptions struct {
	Kind          string
	RootParent    string
	PlanParent    string
	TrustInstance string
	Limit         int
	Interval      time.Duration
	Budget        time.Duration
	Apply         bool
}

// partialBackupReclaimer は用途を必ず明示させ、完成出力用の回収へ切り替えない。
func partialBackupReclaimer(kind string) (signedBackupReclaimer, error) {
	switch kind {
	case "body":
		return reclaimPartialBackup, nil
	case "keys":
		return reclaimPartialBackupKeys, nil
	default:
		return nil, errors.New("partial backup kind must be body or keys")
	}
}

// SweepPartialBackups は未完成出力の子nameと別親のname.jsonを最大limit組巡回する。
// 期限切れapplyだけ回収する。完成/未知/認証不能な出力を保持し、後続へ進んで拒否JSONを返す。
func SweepPartialBackups(ctx context.Context, kind, roots, plans, trust, after string, limit int, apply bool) (report BackupSweepReport, err error) {
	report.Items = []BackupSweepItem{}
	if _, err = partialBackupReclaimer(kind); err != nil {
		return report, err
	}
	if err = validatePlannedKeysSweep(roots, plans, trust, after, limit); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	lock, err := platform.Lock(roots)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, platform.Unlock(lock)) }()
	return sweepPartialBackups(ctx, kind, roots, plans, trust, after, limit, apply, time.Now)
}

// sweepPartialBackups は呼出し側の親排他下で用途別認証を共有巡回へ接続する。
func sweepPartialBackups(ctx context.Context, kind, roots, plans, trust, after string, limit int, apply bool, clock func() time.Time) (BackupSweepReport, error) {
	reclaim, e := partialBackupReclaimer(kind)
	if e != nil {
		return BackupSweepReport{Items: []BackupSweepItem{}}, e
	}
	return sweepSignedBackupPlans(ctx, roots, plans, trust, after, limit, apply, clock, reclaim)
}

// RunBackupPartialMaintenance は即時一回、その後は完了からinterval待機して巡回する。
// 単発と同じ親.lockを保持し、両親device/inodeとtrust bytesの差替えを拒否する。
func RunBackupPartialMaintenance(ctx context.Context, o BackupPartialMaintenanceOptions, emit func(BackupMaintenanceReport) error) error {
	return runBackupPartialMaintenance(ctx, o, emit, waitReplayMaintenance)
}

// runBackupPartialMaintenance は既存署名計画watchの周期/予算/cursor/停止処理を共有する。
func runBackupPartialMaintenance(ctx context.Context, o BackupPartialMaintenanceOptions, emit func(BackupMaintenanceReport) error, wait func(context.Context, time.Duration) error) error {
	if _, e := partialBackupReclaimer(o.Kind); e != nil {
		return e
	}
	base := BackupKeysMaintenanceOptions{o.RootParent, o.PlanParent, o.TrustInstance, o.Limit, o.Interval, o.Budget, o.Apply}
	return runBackupKeysMaintenance(ctx, base, emit, wait, func(ctx context.Context, roots, plans, trust, after string, limit int, apply bool, clock func() time.Time) (BackupSweepReport, error) {
		return sweepPartialBackups(ctx, o.Kind, roots, plans, trust, after, limit, apply, clock)
	})
}
