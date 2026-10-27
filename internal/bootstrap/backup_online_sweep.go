// 完成ペアを優先し、ペア未作成のオンライン出力は事前署名された集合だけ回収する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/store"
)

// OnlineBackupSweepReport は有界巡回の結果。拒否した子を保持し、同じ子への用途切替をしない。
type OnlineBackupSweepReport struct {
	Replay        *ReplaySweepReport      `json:"replay,omitempty"`
	ReplayPending bool                    `json:"replay_pending"`
	Items         []OnlineBackupSweepItem `json:"items"`
	Next          string                  `json:"next_after"`
	More          bool                    `json:"more"`
	Rejected      int                     `json:"rejected_count"`
}

// OnlineBackupSweepItem は本文や鍵を含まない一組の結果。
type OnlineBackupSweepItem struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// SweepOnlineBackups は本文/鍵親の排他を取り、期限切れ完成組と途中出力を認証回収する。
// apply=falseはプレビュー。署名不正・未知ファイル・root差替えは保持して拒否を報告する。
func SweepOnlineBackups(ctx context.Context, o BackupPreparationMaintenanceOptions, after string, limit int, apply bool) (report OnlineBackupSweepReport, err error) {
	return SweepOnlineBackupLifecycle(ctx, o, after, "", limit, apply)
}
func sweepOnlineBackups(ctx context.Context, o BackupPreparationMaintenanceOptions, after string, limit int, apply bool, clock func() time.Time) (report OnlineBackupSweepReport, err error) {
	report.Items = []OnlineBackupSweepItem{}
	names, e := backupPairSweepNames(ctx, o.CopyParent, o.KeysParent, after)
	if e != nil {
		return report, e
	}
	report.Next = after
	for i, name := range names {
		if i == limit {
			report.More = true
			break
		}
		if e = ctx.Err(); e != nil {
			report.More = true
			return report, e
		}
		body, keys := filepath.Join(o.CopyParent, name), filepath.Join(o.KeysParent, name)
		status, e := reclaimOnlineBackupItem(ctx, o, name, body, keys, apply, clock)
		report.Items = append(report.Items, OnlineBackupSweepItem{name, status})
		if ctx.Err() != nil {
			report.More = true
			return report, ctx.Err()
		}
		report.Next = name
		if e != nil {
			report.Rejected++
		}
	}
	if report.Rejected > 0 {
		return report, ErrBackupSweepRejected
	}
	return report, nil
}
func reclaimOnlineBackupItem(ctx context.Context, o BackupPreparationMaintenanceOptions, name, body, keys string, apply bool, clock func() time.Time) (string, error) {
	pair := filepath.Join(o.PairPlanParent, name+".json")
	if _, e := os.Lstat(pair); e == nil {
		r, e := reclaimBackupPairLocked(ctx, body, keys, o.TrustInstance, pair, apply, clock, func(string) error { return nil })
		if e != nil {
			return "rejected", e
		}
		if r.Applied {
			return "reclaimed", nil
		}
		if r.Expired {
			return "expired", nil
		}
		return "retained", nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return "rejected", e
	}
	bodyExists, e := onlineRootExists(body)
	if e != nil {
		return "rejected", e
	}
	keysExists, e := onlineRootExists(keys)
	if e != nil {
		return "rejected", e
	}
	if !bodyExists && !keysExists {
		return "gone", nil
	}
	// 全存在rootをプレビュー照合してから本文を先に消す。鍵は本文がなくなった後だけ。
	var br, kr BackupReport
	if bodyExists {
		br, e = reclaimOnlinePartial(ctx, body, o.TrustInstance, filepath.Join(o.PartialPlanParent, name+".json"), false, clock)
		if e != nil {
			return "rejected", e
		}
	}
	if keysExists {
		kr, e = reclaimOnlineKeysInventory(ctx, keys, o.TrustInstance, filepath.Join(o.PartialKeysPlanParent, name+".json"), false, clock)
		if e != nil {
			return "rejected", e
		}
	}
	expired := (!bodyExists || br.Expired) && (!keysExists || kr.Expired)
	if !expired {
		return "retained", nil
	}
	if !apply {
		return "expired", nil
	}
	if bodyExists {
		br, e = reclaimOnlinePartial(ctx, body, o.TrustInstance, filepath.Join(o.PartialPlanParent, name+".json"), true, clock)
		if e != nil || !br.Applied {
			return "rejected", errors.Join(e, errors.New("body inventory cleanup incomplete"))
		}
	}
	if keysExists {
		kr, e = reclaimOnlineKeysInventory(ctx, keys, o.TrustInstance, filepath.Join(o.PartialKeysPlanParent, name+".json"), true, clock)
		if e != nil || !kr.Applied {
			return "rejected", errors.Join(e, errors.New("keys inventory cleanup incomplete"))
		}
	}
	return "reclaimed", nil
}
func onlineRootExists(path string) (bool, error) {
	_, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	return e == nil, e
}

// reclaimOnlineKeysInventory はv2事前計画が許可した完成印も扱う。旧部分計画は用途外。
func reclaimOnlineKeysInventory(ctx context.Context, root, trust, plan string, apply bool, clock func() time.Time) (report BackupReport, err error) {
	if err = backupKeysPlanPaths(root, trust, plan); err != nil {
		return report, err
	}
	marker, trustRaw, e := loadBackupTrust(trust)
	if e != nil {
		return report, e
	}
	raw, e := readPrivate(plan, backupKeysPlanLimit)
	if e != nil {
		return report, e
	}
	p, e := decodePartialKeysPlan(raw, marker, trustRaw)
	if e != nil {
		return report, e
	}
	if p.Schema != 3 || p.Mode != "expired_online_keys_inventory" {
		return report, errors.New("online key inventory purpose required")
	}
	dev, inode, e := replayRootIdentity(root)
	if e != nil {
		return report, e
	}
	if p.Root != root || p.Plan != plan || dev != p.Device || inode != p.Inode {
		return report, errors.New("online keys inventory identity mismatch")
	}
	if clock().UnixNano() < int64(p.Bundle.Created) {
		return report, errors.New("online keys inventory clock regression")
	}
	report = backupKeysReclaimReport(p.Bundle, clock())
	files, dirs := backupKeysInventory()
	files["bundle.pending"] = true
	if e = walkBackupInventory(ctx, root, files, dirs, true); e != nil {
		return report, e
	}
	if e = validatePartialKeysLengths(ctx, root, p); e != nil {
		return report, e
	}
	completed, e := readPrivate(filepath.Join(root, "bundle.json"), backupKeysLimit)
	if e == nil {
		if len(completed) != int(p.BundleBytes) || sha256.Sum256(completed) != p.BundleSHA {
			return report, errors.New("online completed bundle mismatch")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return report, e
	}
	if !apply || !report.Expired {
		return report, nil
	}
	if e = reclaimBackupInventoryWithMissingManifest(ctx, root, files, dirs, "bundle.json", true, func(stage string) error {
		if stage == "backup:reclaim_manifest" {
			return retireBackupCleanupPlan(plan, raw, backupKeysPlanLimit)
		}
		return nil
	}); e != nil {
		return report, e
	}
	report.Applied = true
	return report, store.SyncDirectory(filepath.Dir(root))
}

// validateOnlineSweepPaths は全回収親と信頼根の重複・内包を拒否する。
func validateOnlineSweepPaths(o BackupPreparationMaintenanceOptions) error {
	paths := []string{o.CopyParent, o.KeysParent, o.PartialPlanParent, o.PartialKeysPlanParent, o.PairPlanParent, o.WorkParent, o.TrustInstance}
	for i, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("online sweep requires clean absolute paths")
		}
		for _, other := range paths[:i] {
			if e := separateBackupPaths(p, other); e != nil {
				return e
			}
		}
		if i < len(paths)-1 {
			if e := privatePath(p, true); e != nil {
				return e
			}
		}
	}
	return nil
}
