// 外部署名計画と鍵束を名前で対応付け、正本不要の期限回収を有界巡回する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/platform"
)

// SweepPlannedBackupKeys はkeysの子nameとplans/name.jsonを最大limit組検査する。
// 同じkeys親の巡回/watchを非待機排他する。期限切れapplyだけ鍵束を回収し、
// 使用済み計画は保持する。拒否は保持して後続へ進み、部分結果とエラーを返す。
func SweepPlannedBackupKeys(ctx context.Context, keys, plans, trust, after string, limit int, apply bool) (report BackupSweepReport, err error) {
	report.Items = []BackupSweepItem{}
	if err = validatePlannedKeysSweep(keys, plans, trust, after, limit); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	lock, err := platform.Lock(keys)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, platform.Unlock(lock)) }()
	return sweepPlannedBackupKeys(ctx, keys, plans, trust, after, limit, apply, time.Now)
}

// validatePlannedKeysSweep は信頼根を両親から分離し、所有者限定の入力を検査する。
func validatePlannedKeysSweep(keys, plans, trust, after string, limit int) error {
	if limit < 1 || limit > 128 || after != "" && !validBackupSweepName(after) {
		return errors.New("planned key sweep requires limit 1..128 and a non-hidden basename cursor")
	}
	if e := backupKeysPlanPaths(keys, trust, plans); e != nil {
		return e
	}
	for _, parent := range []string{keys, plans} {
		if e := privatePath(parent, true); e != nil {
			return e
		}
	}
	_, _, e := loadBackupTrust(trust)
	return e
}

// sweepPlannedBackupKeys は呼出し側が鍵親の排他を保持した状態で巡回する。
// 親全体4096entryを削除前に検査し、ドット名を除外する。計画だけの子は走査しない。
func sweepPlannedBackupKeys(ctx context.Context, keys, plans, trust, after string, limit int, apply bool, clock func() time.Time) (report BackupSweepReport, err error) {
	return sweepSignedBackupPlans(ctx, keys, plans, trust, after, limit, apply, clock, reclaimBackupKeysPlanned)
}

// signedBackupReclaimer は外部署名計画で認証する用途別回収処理。
type signedBackupReclaimer func(context.Context, string, string, string, bool, func() time.Time, func(string) error) (BackupReport, error)

// sweepSignedBackupPlans は完成鍵束/未完成本文/未完成鍵束の列挙・ページ・拒否報告を共有する。
func sweepSignedBackupPlans(ctx context.Context, keys, plans, trust, after string, limit int, apply bool, clock func() time.Time, reclaimItem signedBackupReclaimer) (report BackupSweepReport, err error) {
	report.Items = []BackupSweepItem{}
	if err = validatePlannedKeysSweep(keys, plans, trust, after, limit); err != nil {
		return report, err
	}
	names, err := boundedBackupNames(ctx, keys, after, validBackupSweepName)
	if err != nil {
		return report, err
	}
	for i, name := range names {
		if i == limit {
			report.More = true
			break
		}
		if err = ctx.Err(); err != nil {
			report.More = true
			return report, err
		}
		item := BackupSweepItem{Name: name, Status: "rejected"}
		root := filepath.Join(keys, name)
		if _, e := os.Lstat(root); errors.Is(e, os.ErrNotExist) {
			item.Status = "gone"
		} else {
			reclaim, e := reclaimItem(ctx, root, trust, filepath.Join(plans, name+".json"), apply, clock, func(string) error { return nil })
			if err = ctx.Err(); err != nil {
				report.More = true
				return report, err
			}
			if e == nil {
				item.Status = "retained"
				if reclaim.Expired {
					item.Status = "expired"
				}
				if reclaim.Applied {
					item.Status = "reclaimed"
				}
				item.Reclaim = &reclaim
			}
		}
		report.Items = append(report.Items, item)
		report.Next = name
		if item.Status == "rejected" {
			report.Rejected++
		}
	}
	if report.Rejected > 0 {
		return report, ErrBackupSweepRejected
	}
	return report, nil
}
