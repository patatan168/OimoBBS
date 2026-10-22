// 別親に同名で保管したコピーと鍵束を対応付け、期限切れ本文だけを有界巡回する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrBackupSweepRejected は保持した不正な組を報告書で確認する必要があることを示す。
var ErrBackupSweepRejected = errors.New("backup sweep contains rejected pairs; inspect report")

// BackupSweepItem は鍵や本文を含まない一組の結果。Reclaimは認証成功時だけ設定する。
type BackupSweepItem struct {
	Name    string        `json:"name"`
	Status  string        `json:"status"`
	Reclaim *BackupReport `json:"reclaim,omitempty"`
}

// BackupSweepReport は本文または鍵束巡回の完了済み位置と部分結果。公開復元は行わない。
type BackupSweepReport struct {
	Items        []BackupSweepItem `json:"items"`
	Next         string            `json:"next_after"`
	More         bool              `json:"more"`
	Rejected     int               `json:"rejected_count"`
	RestoreReady bool              `json:"restore_ready"`
}

// SweepExpiredBackups は別々の0700親にある同名のコピー/鍵束を最大limit組検査する。
// afterは前回next_afterか空、limitは1〜128。期限切れかつapply時だけ本文を回収する。
// 親全体4096entryを削除前に検査する。認証失敗は保持して後続へ進み、部分結果とエラーを返す。
// ドット名は対象外。同じコピーの作成・照合・回収を同時に実行しないこと。
func SweepExpiredBackups(ctx context.Context, copies, keys, after string, limit int, apply bool) (BackupSweepReport, error) {
	return sweepExpiredBackups(ctx, copies, keys, after, limit, apply, time.Now)
}

func sweepExpiredBackups(ctx context.Context, copies, keys, after string, limit int, apply bool, clock func() time.Time) (report BackupSweepReport, err error) {
	report.Items = []BackupSweepItem{}
	if limit < 1 || limit > 128 || after != "" && !validBackupSweepName(after) {
		return report, errors.New("expired backup sweep requires limit 1..128 and a non-hidden basename cursor")
	}
	if err = separateBackupPaths(copies, keys); err != nil {
		return report, err
	}
	for _, parent := range []string{copies, keys} {
		if err = privatePath(parent, true); err != nil {
			return report, err
		}
	}
	names, err := boundedBackupNames(ctx, copies, after, validBackupSweepName)
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
		root := filepath.Join(copies, name)
		if _, e := os.Lstat(root); errors.Is(e, os.ErrNotExist) {
			item.Status = "gone"
		} else {
			reclaim, e := reclaimBackupWithKeys(ctx, root, filepath.Join(keys, name), apply, clock, func(string) error { return nil })
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

func validBackupSweepName(name string) bool {
	return name != "" && len(name) <= 255 && !strings.HasPrefix(name, ".") && filepath.Base(name) == name && !strings.ContainsRune(name, '\x00')
}
