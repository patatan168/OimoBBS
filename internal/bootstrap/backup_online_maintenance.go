// 稼働Repositoryの定期捕捉と、新規同名本文/鍵束/署名計画の生成を接続する。
package bootstrap

import (
	"context"
	"errors"
	"path/filepath"

	"oimobbs/internal/board"
	"oimobbs/internal/store"
)

// PrepareNextOnlineBackup は稼働正本を閉じず、専用親へ新しい完成組を作る。Apply=falseは配置検査のみ。
func (r *Repository) PrepareNextOnlineBackup(ctx context.Context, o BackupPreparationMaintenanceOptions, capture OnlineBackupSiteOptions) (report BackupPreparationMaintenanceReport, err error) {
	if err = validatePreparationMaintenance(r.cfg, o); err != nil {
		return report, err
	}
	unlock, e := lockBackupDirectories(o.ControlParent)
	if e != nil {
		return report, e
	}
	defer func() { err = errors.Join(err, unlock()) }()
	batch, cancel := context.WithTimeout(ctx, o.Budget)
	defer cancel()
	return r.prepareNextOnlineBackup(batch, o, capture)
}

func (r *Repository) prepareNextOnlineBackup(ctx context.Context, o BackupPreparationMaintenanceOptions, capture OnlineBackupSiteOptions) (report BackupPreparationMaintenanceReport, err error) {
	report.Status = "failed"
	report.Apply = o.Apply
	if err = validatePreparationMaintenance(r.cfg, o); err != nil {
		return report, err
	}
	if err = checkPreparationEntryLimits(ctx, o.parents()[:6]); err != nil {
		return report, err
	}
	if !o.Apply {
		report.Status = "preview"
		return report, nil
	}
	// 監査移管を独立した準備工程として済ませてから捕捉境界を取る。
	r.mu.Lock()
	budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
	err = r.catchUpAudit(ctx, &budget)
	r.mu.Unlock()
	if err != nil {
		return report, err
	}
	name, e := newPreparationName(o)
	if e != nil {
		return report, e
	}
	report.Name = name
	options := OnlineBackupPreparationOptions{Capture: capture, TrustInstance: o.TrustInstance, PartialPlan: filepath.Join(o.PartialPlanParent, name+".json"), PartialKeysPlan: filepath.Join(o.PartialKeysPlanParent, name+".json"), PairPlan: filepath.Join(o.PairPlanParent, name+".json")}
	options.CleanupKey = o.CleanupKey
	preparation, e := r.PrepareOnlineBackup(ctx, filepath.Join(o.CopyParent, name), filepath.Join(o.KeysParent, name), o.WorkParent, options)
	report.Preparation = &preparation
	if e != nil {
		if onlyOnlinePreparationBusy(e) {
			report.Status = "deferred_busy"
			return report, nil
		}
		report.Status = backupMaintenanceStatus(e)
		return report, e
	}
	if !preparation.Complete {
		return report, errors.New("online preparation returned incomplete success")
	}
	report.Status = "completed"
	return report, nil
}

// RunOnlineBackupMaintenance は既定毎時の新規捕捉を接続し、保存先/信頼根変更で停止する。
// 既存の完成ペア/鍵束/本文回収watchと同じ認証形式を使う。失敗成果は回収計画へ委ねる。
func (r *Repository) RunOnlineBackupMaintenance(ctx context.Context, o BackupPreparationMaintenanceOptions, capture OnlineBackupSiteOptions, emit func(BackupPreparationMaintenanceReport) error) error {
	if _, _, e := normalizeOnlineSiteOptions(capture); e != nil {
		return e
	}
	after := ""
	workAfter := ""
	return runBackupPreparationMaintenance(ctx, r.cfg, o, emit, waitReplayMaintenance, func(ctx context.Context, _ Config, o BackupPreparationMaintenanceOptions) (BackupPreparationMaintenanceReport, error) {
		cleanup, e := SweepOnlineBackupLifecycle(ctx, o, after, workAfter, 128, o.Reclaim)
		if e != nil {
			if onlyPreparationBusy(e) {
				return BackupPreparationMaintenanceReport{Status: "deferred_busy", Apply: o.Apply, Cleanup: &cleanup}, nil
			}
			return BackupPreparationMaintenanceReport{Status: backupMaintenanceStatus(e), Apply: o.Apply, Cleanup: &cleanup}, e
		}
		workAfter = ""
		if cleanup.Replay != nil && cleanup.Replay.More {
			workAfter = cleanup.Replay.Next
		}
		if cleanup.ReplayPending && o.Reclaim {
			return BackupPreparationMaintenanceReport{Status: "deferred_busy", Apply: o.Apply, Cleanup: &cleanup}, nil
		}
		after = ""
		if cleanup.More {
			after = cleanup.Next
		}
		report, e := r.prepareNextOnlineBackup(ctx, o, capture)
		report.Cleanup = &cleanup
		if onlyOnlineBackupCapacity(e) {
			report.Status = "deferred_capacity"
			return report, nil
		}
		return report, e
	})
}

// onlyOnlinePreparationBusy は解放/Sync等の実エラーが併記された失敗を延期成功へ変換しない。
func onlyOnlinePreparationBusy(err error) bool {
	if err == nil {
		return false
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		children := many.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyOnlinePreparationBusy(child) {
				return false
			}
		}
		return true
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return onlyOnlinePreparationBusy(one.Unwrap())
	}
	return err == ErrOnlineBackupBusy || err == board.ErrBusy || err == ErrOnlineBackupChanged
}

// onlyOnlineBackupCapacity は容量予約の拒否だけを延期し、併記された保存・解放エラーは停止させる。
func onlyOnlineBackupCapacity(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyOnlineBackupCapacity(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyOnlineBackupCapacity(wrapped.Unwrap())
	}
	return err == ErrOnlineBackupCapacity
}
