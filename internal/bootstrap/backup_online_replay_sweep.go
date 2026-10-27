// 全オンライン鍵束へ作業領域を束縛し、再生用コピーを本文・鍵束より先に回収する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

// sweepOnlineReplay は親排他を呼出元が保持した状態で、認証済み鍵束の索引と有界巡回を行う。
// 作業計画の未認証SHAは候補選択だけに使い、削除許可は従来のMAC・inode・完全集合検査へ委ねる。
func sweepOnlineReplay(ctx context.Context, o BackupPreparationMaintenanceOptions, after string, limit int, apply bool) (report ReplaySweepReport, err error) {
	report.Items = []ReplaySweepItem{}
	report.Next = after
	if limit < 1 || limit > 128 || after != "" && !validReplaySweepName(after) {
		return report, errors.New("invalid online replay cursor or limit")
	}
	names, e := replaySweepNames(ctx, o.WorkParent, after)
	if e != nil {
		return report, e
	}
	if len(names) == 0 {
		return report, nil
	}
	trust, _, e := loadBackupTrust(o.TrustInstance)
	if e != nil {
		return report, e
	}
	keyNames, e := boundedBackupNames(ctx, o.KeysParent, "", validBackupSweepName)
	if e != nil {
		return report, e
	}
	index := map[domain.Hash]string{}
	ambiguous := map[domain.Hash]bool{}
	for _, name := range keyNames {
		if e = ctx.Err(); e != nil {
			return report, e
		}
		root := filepath.Join(o.KeysParent, name)
		bundle, e := loadBackupKeys(ctx, root)
		if e != nil {
			continue
		} // 部分/不正束は削除許可に使わず、対応rootは拒否して保持する。
		var marker instance
		raw, e := readPrivate(filepath.Join(root, "instance.json"), 4096)
		if e != nil || decodeBackupInstance(raw, &marker) != nil || marker != trust || bundle.Mode != "online_keys" {
			continue
		}
		if _, exists := index[bundle.BackupSHA]; exists {
			ambiguous[bundle.BackupSHA] = true
		}
		index[bundle.BackupSHA] = root
	}
	for i, name := range names {
		if i == limit {
			report.More = true
			break
		}
		if e = ctx.Err(); e != nil {
			report.More = true
			return report, e
		}
		root := filepath.Join(o.WorkParent, name)
		item := ReplaySweepItem{Name: name, Status: "rejected"}
		independent := false
		if o.CleanupKey != "" {
			if _, gateErr := os.Lstat(filepath.Join(root, independentReplayGate)); !errors.Is(gateErr, os.ErrNotExist) {
				independent = true
				result, cleanupErr := ReclaimBackupReplayWithCleanupKey(ctx, root, o.CleanupKey, apply)
				if ctx.Err() != nil {
					return report, ctx.Err()
				}
				if errors.Is(cleanupErr, errReplayRootBusy) {
					item.Status = "busy"
				} else if cleanupErr == nil {
					item.Status = "verified"
					if result.Applied {
						item.Status = "reclaimed"
					}
					item.Reclaim = &result
				}
			}
		}
		raw, e := readPrivate(filepath.Join(root, backupReplayGate), replayCleanupLimit)
		var envelope backupEnvelope
		var hint replayCleanupPlan
		if !independent && e == nil && strictjson.Decode(raw, &envelope) == nil && strictjson.Decode(envelope.Manifest, &hint) == nil {
			if keys, ok := index[hint.BackupSHA]; ok && !ambiguous[hint.BackupSHA] {
				item, e = sweepReplayRoot(ctx, root, keys, apply)
				if e != nil {
					report.More = true
					return report, e
				}
			}
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
	if report.Rejected > 0 {
		return report, ErrReplaySweepRejected
	}
	return report, nil
}

// SweepOnlineBackupLifecycle は作業・本文・鍵親を一括排他し、再生作業を先に認証回収する。
// workAfterは前回Replay.Next。作業rootが残る間は本文/鍵の回収を延期し、未知rootを保持する。
func SweepOnlineBackupLifecycle(ctx context.Context, o BackupPreparationMaintenanceOptions, after, workAfter string, limit int, apply bool) (report OnlineBackupSweepReport, err error) {
	report.Items = []OnlineBackupSweepItem{}
	if o.CleanupKey != "" {
		if err = validateIndependentCleanupPaths(o.CleanupKey, append(o.parents(), o.TrustInstance)...); err != nil {
			return report, err
		}
	}
	if err = validateOnlineSweepPaths(o); err != nil {
		return report, err
	}
	if err = validateBackupPairSweep(o.CopyParent, o.KeysParent, o.PairPlanParent, o.TrustInstance, after, limit); err != nil {
		return report, err
	}
	for _, p := range []string{o.PartialPlanParent, o.PartialKeysPlanParent} {
		if err = validatePlannedKeysSweep(o.CopyParent, p, o.TrustInstance, after, limit); err != nil {
			return report, err
		}
	}
	unlock, e := lockBackupDirectories(o.CopyParent, o.KeysParent, o.WorkParent)
	if e != nil {
		return report, e
	}
	defer func() { err = errors.Join(err, unlock()) }()
	work, e := sweepOnlineReplay(ctx, o, workAfter, limit, apply)
	report.Replay = &work
	if e != nil {
		return report, e
	}
	// 全ページの現在の残存集合を確認する。前のpageのbusyや新しいrootを見落として鍵を消さない。
	remaining, e := replaySweepNames(ctx, o.WorkParent, "")
	if e != nil {
		return report, e
	}
	if len(remaining) > 0 {
		report.ReplayPending = true
		report.Next = after
		return report, nil
	}
	bodies, e := sweepOnlineBackups(ctx, o, after, limit, apply, time.Now)
	bodies.Replay = &work
	return bodies, e
}
