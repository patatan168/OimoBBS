// 切替済みの旧WALだけを、現行世代と監査の照合後に停止中CLIから回収する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// ControlReclaimReport は今回列挙した旧WALの件数・論理byte数を返す。物理解放量ではない。
type ControlReclaimReport struct {
	Owners   int        `json:"owners"`
	Files    int        `json:"files"`
	Bytes    domain.U64 `json:"bytes"`
	Verified bool       `json:"verified"`
	Applied  bool       `json:"applied"`
}

type controlReclaimItem struct {
	dir   string
	bytes domain.U64
}

// ReclaimControlWAL は停止中専用。apply=falseでは削除せず、trueでは照合後にunlinkと親Syncを行う。
// 一部回収後の失敗は同じ操作で再開する。日別監査・現行snapshot/delta・外部候補は変更しない。
func ReclaimControlWAL(ctx context.Context, cfg Config, apply bool, capture func([]byte) error) (ControlReclaimReport, error) {
	return reclaimControlWAL(ctx, cfg, apply, capture, func(string) {})
}

func reclaimControlWAL(ctx context.Context, cfg Config, apply bool, capture func([]byte) error, checkpoint func(string)) (report ControlReclaimReport, err error) {
	if capture == nil {
		return report, errors.New("posting capture validator required")
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	repo, err := OpenPostingRepository(cfg, capture)
	if err != nil {
		return report, err
	}
	defer func() {
		err = errors.Join(err, repo.Close())
		if err != nil {
			report = ControlReclaimReport{}
		}
	}()
	proof, err := repo.VerifyAuditTransfer(ctx)
	if err != nil {
		return report, err
	}
	if !proof.Complete {
		return report, errors.New("audit transfer must be complete before reclaim")
	}
	items, dirs, err := repo.controlReclaimPlan(ctx)
	if err != nil {
		return report, err
	}
	report = ControlReclaimReport{Owners: len(dirs), Files: len(items), Verified: true}
	for _, item := range items {
		report.Bytes += item.bytes
	}
	if !apply {
		return report, nil
	}
	for _, item := range items {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		if err = os.Remove(filepath.Join(item.dir, "control-000001.wal")); err != nil {
			return report, err
		}
		checkpoint("reclaim_unlink")
		if err = store.SyncDirectory(item.dir); err != nil {
			return report, err
		}
		checkpoint("reclaim_directory_sync")
	}
	// unlink直後の中断から再実行した場合、既に空の対象にも親Syncを行う。
	for _, dir := range dirs {
		if err = store.SyncDirectory(dir); err != nil {
			return report, err
		}
	}
	report.Applied = true
	return report, nil
}

// controlReclaimPlan は全所有者を照合してから削除対象を返す。初回移行の第1世代だけを扱う。
func (r *Repository) controlReclaimPlan(ctx context.Context) ([]controlReclaimItem, []string, error) {
	key, err := controlAnchorKey(r.cfg.DataDir)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key[:])
	ids := make([]domain.ID, 0, len(r.anchors))
	for id := range r.anchors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	items := []controlReclaimItem{}
	dirs := []string{}
	budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return nil, nil, err
		}
		a := r.anchors[id]
		dir := controlOwnerPath(r.cfg.DataDir, a.Kind, id)
		generation, err := inspectControlGeneration(dir, a.Kind, id, siteID(r.site.State()), key)
		if err != nil {
			return nil, nil, err
		}
		if generation.Manifest.Generation != 2 || len(generation.Pending) != 0 {
			return nil, nil, errors.New("reclaim requires a completed first snapshot activation")
		}
		dirs = append(dirs, dir)
		for _, name := range generation.Retained {
			if name != "control-000001.wal" {
				return nil, nil, store.ErrCorrupt
			}
			size, err := inspectRetiredControl(ctx, dir, a, &budget)
			if err != nil {
				return nil, nil, err
			}
			items = append(items, controlReclaimItem{dir, size})
		}
	}
	return items, dirs, nil
}
