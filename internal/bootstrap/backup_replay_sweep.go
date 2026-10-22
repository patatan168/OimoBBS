// 停止した再生作業領域を件数上限付きで巡回し、認証付き単独回収へ接続する。
package bootstrap

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const replaySweepEntryLimit = 4096

// ErrReplaySweepRejected は一部の領域を安全に回収できず、確認が必要なことを示す。
var ErrReplaySweepRejected = errors.New("replay sweep contains rejected roots; inspect report")

// ReplaySweepItem は本文や鍵、詳細な認証エラーを含まない領域単位の結果。
type ReplaySweepItem struct {
	Name    string               `json:"name"`
	Status  string               `json:"status"`
	Reclaim *ReplayReclaimReport `json:"reclaim,omitempty"`
}

// ReplaySweepReport は巡回結果と次ページの位置。busy/rejectedは次の巡回で再確認する。
type ReplaySweepReport struct {
	Items        []ReplaySweepItem `json:"items"`
	Next         string            `json:"next_after"`
	More         bool              `json:"more"`
	Rejected     int               `json:"rejected_count"`
	Busy         int               `json:"busy_count"`
	RestoreReady bool              `json:"restore_ready"`
}

// SweepBackupReplay は同じ別保管鍵に対応する作業領域を名前順に最大limit件検査する。
// apply時だけ停止済みの認証済み領域を回収する。afterは前回next_afterか空文字。
// 親の列挙は4096entryまで、limitは1〜128。別backup、リンク、未知fileは残して拒否する。
func SweepBackupReplay(ctx context.Context, parent, keys, after string, limit int, apply bool) (report ReplaySweepReport, err error) {
	report.Items = []ReplaySweepItem{}
	if limit < 1 || limit > 128 || after != "" && !validReplaySweepName(after) {
		return report, errors.New("replay sweep requires limit 1..128 and a replay basename cursor")
	}
	if err = separateBackupPaths(parent, keys); err != nil {
		return report, err
	}
	if err = privatePath(parent, true); err != nil {
		return report, err
	}
	// 不正な共通鍵で巡回を始めず、各rootでも認証と束縛を再検査する。
	if _, err = loadBackupKeys(ctx, keys); err != nil {
		return report, err
	}
	names, err := replaySweepNames(ctx, parent, after)
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
		item, e := sweepReplayRoot(ctx, filepath.Join(parent, name), keys, apply)
		if e != nil {
			report.More = true
			return report, e
		}
		report.Items = append(report.Items, item)
		report.Next = name
		if item.Status == "rejected" {
			report.Rejected++
		}
		if item.Status == "busy" {
			report.Busy++
		}
	}
	if report.Rejected != 0 {
		return report, ErrReplaySweepRejected
	}
	return report, nil
}

func validReplaySweepName(name string) bool {
	return len(name) <= 255 && len(name) > len(".backup-replay-") && strings.HasPrefix(name, ".backup-replay-") && filepath.Base(name) == name && !strings.ContainsRune(name, '\x00')
}

// replaySweepNames は削除を始める前に親の件数制限を検査し、安定した名前順へ並べる。
func replaySweepNames(ctx context.Context, parent, after string) ([]string, error) {
	return boundedBackupNames(ctx, parent, after, validReplaySweepName)
}

// boundedBackupNames は親全体の上限を先に検査し、処理対象だけを名前順に返す。
func boundedBackupNames(ctx context.Context, parent, after string, valid func(string) bool) ([]string, error) {
	f, err := os.Open(parent)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names := []string{}
	total := 0
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		entries, e := f.ReadDir(128)
		total += len(entries)
		if total > replaySweepEntryLimit {
			return nil, errors.New("backup sweep parent exceeds 4096 entries")
		}
		for _, entry := range entries {
			if valid(entry.Name()) && entry.Name() > after {
				names = append(names, entry.Name())
			}
		}
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return nil, e
		}
	}
	slices.Sort(names)
	return names, nil
}

// sweepReplayRoot は稼働中を延期し、失敗した領域の詳細を出力せず次の領域へ進める。
func sweepReplayRoot(ctx context.Context, root, keys string, apply bool) (ReplaySweepItem, error) {
	item := ReplaySweepItem{Name: filepath.Base(root), Status: "rejected"}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		item.Status = "gone"
		return item, nil
	}
	report, err := ReclaimBackupReplay(ctx, root, keys, apply)
	if ctx.Err() != nil {
		return item, ctx.Err()
	}
	if errors.Is(err, errReplayRootBusy) {
		item.Status = "busy"
	} else if err == nil {
		item.Status = "verified"
		if report.Applied {
			item.Status = "reclaimed"
		}
		item.Reclaim = &report
	}
	return item, nil
}
