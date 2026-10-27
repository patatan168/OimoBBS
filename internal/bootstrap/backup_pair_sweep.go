// 本文親と鍵親の子名を合併し、正本不要の順序付きペア回収を有界巡回する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// BackupPairSweepItem は一組の処理結果。Pairは認証済みの結果だけを含む。
type BackupPairSweepItem struct {
	Name   string            `json:"name"`
	Status string            `json:"status"`
	Pair   *BackupPairReport `json:"pair,omitempty"`
}

// BackupPairSweepReport は完了cursorと部分結果。More時はNextから未完了組を再試行する。
type BackupPairSweepReport struct {
	Items        []BackupPairSweepItem `json:"items"`
	Rejected     int                   `json:"rejected_count"`
	Next         string                `json:"next_after"`
	More         bool                  `json:"more"`
	RestoreReady bool                  `json:"restore_ready"`
}

// SweepBackupPairs は両親を非待機排他し、同名本文/鍵束とplans/name.jsonを巡回する。
// 片側欠落も列挙し、署名計画で本文削除済みの場合だけ鍵回収を再開する。
func SweepBackupPairs(ctx context.Context, bodies, keys, plans, trust, after string, limit int, apply bool) (report BackupPairSweepReport, err error) {
	report.Items = []BackupPairSweepItem{}
	if err = validateBackupPairSweep(bodies, keys, plans, trust, after, limit); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	unlock, err := lockBackupDirectories(bodies, keys)
	if err != nil {
		return report, err
	}
	defer func() {
		if e := unlock(); e != nil {
			err = errors.Join(err, e)
		}
	}()
	return sweepBackupPairs(ctx, bodies, keys, plans, trust, after, limit, apply, time.Now)
}

func validateBackupPairSweep(bodies, keys, plans, trust, after string, limit int) error {
	if limit < 1 || limit > 128 || after != "" && !validBackupSweepName(after) {
		return errors.New("pair sweep requires limit 1..128 and basename cursor")
	}
	paths := []string{bodies, keys, plans, trust}
	for i, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("pair sweep requires clean absolute paths")
		}
		for _, other := range paths[:i] {
			if e := separateBackupPaths(path, other); e != nil {
				return e
			}
		}
	}
	for _, parent := range paths[:3] {
		if e := privatePath(parent, true); e != nil {
			return e
		}
	}
	_, _, e := loadBackupTrust(trust)
	return e
}

// backupPairSweepNames は両親を削除前に全件検査し、最大4096の非隠し子名を合併する。
func backupPairSweepNames(ctx context.Context, bodies, keys, after string) ([]string, error) {
	union := map[string]bool{}
	for _, parent := range []string{bodies, keys} {
		names, e := boundedBackupNames(ctx, parent, "", validBackupSweepName)
		if e != nil {
			return nil, e
		}
		for _, name := range names {
			union[name] = true
			if len(union) > 4096 {
				return nil, errors.New("pair sweep union exceeds 4096 entries")
			}
		}
	}
	names := []string{}
	for name := range union {
		if name > after {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

// sweepBackupPairs は親排他下の共通巡回。未完了組をcursorで飛ばさず、物理的な部分結果を残す。
func sweepBackupPairs(ctx context.Context, bodies, keys, plans, trust, after string, limit int, apply bool, clock func() time.Time) (report BackupPairSweepReport, err error) {
	report.Items = []BackupPairSweepItem{}
	if err = validateBackupPairSweep(bodies, keys, plans, trust, after, limit); err != nil {
		return report, err
	}
	names, err := backupPairSweepNames(ctx, bodies, keys, after)
	if err != nil {
		return report, err
	}
	report.Next = after
	for i, name := range names {
		if i == limit {
			report.More = true
			break
		}
		if err = ctx.Err(); err != nil {
			report.More = true
			return report, err
		}
		b, k := filepath.Join(bodies, name), filepath.Join(keys, name)
		item := BackupPairSweepItem{Name: name, Status: "rejected"}
		if pairRootsGone(b, k) {
			item.Status = "gone"
		} else {
			result, e := reclaimBackupPairLocked(ctx, b, k, trust, filepath.Join(plans, name+".json"), apply, clock, func(string) error { return nil })
			if result.Body != nil {
				item.Pair = &result
			}
			if ctx.Err() != nil {
				item.Status = backupMaintenanceStatus(ctx.Err())
				if result.Applied {
					item.Status = "reclaimed"
					report.Next = name
				}
				report.Items = append(report.Items, item)
				report.More = true
				return report, ctx.Err()
			}
			if e == nil {
				item.Status = "retained"
				if result.Expired {
					item.Status = "expired"
				}
				if result.Applied {
					item.Status = "reclaimed"
				}
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

func pairRootsGone(body, keys string) bool {
	_, b := os.Lstat(body)
	_, k := os.Lstat(keys)
	return errors.Is(b, os.ErrNotExist) && errors.Is(k, os.ErrNotExist)
}
