// 外部署名計画と別保管公開信頼根だけで、期限切れ鍵束を認証・回収・中断再開する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// ReclaimBackupKeysPlanned は正本やbundle内の秘密鍵を読まず、署名済みの期限切れ鍵束だけを回収する。
// plan/trustはroot外で保持する。root位置・device/inode・manifest bytes・厳密inventoryを照合する。
// master/seed/manifest削除後も使用前の計画で再開できる。root除去前に計画を使用済みへ同期する。
// 使用済み後の残存rootは手動確認する。同時回収や使用前計画への巻戻しは禁止。
func ReclaimBackupKeysPlanned(ctx context.Context, input, trust, plan string, apply bool) (BackupReport, error) {
	return reclaimBackupKeysPlanned(ctx, input, trust, plan, apply, time.Now, func(string) error { return nil })
}

func reclaimBackupKeysPlanned(ctx context.Context, input, trust, plan string, apply bool, clock func() time.Time, boundary func(string) error) (report BackupReport, err error) {
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = backupKeysPlanPaths(input, trust, plan); err != nil {
		return report, err
	}
	marker, trustRaw, err := loadBackupTrust(trust)
	if err != nil {
		return report, err
	}
	raw, err := readPrivate(plan, backupKeysPlanLimit)
	if err != nil {
		return report, err
	}
	planRaw := raw
	p, err := decodeBackupKeysPlan(raw, marker, trustRaw)
	if err != nil {
		return report, err
	}
	dev, inode, err := replayRootIdentity(input)
	if err != nil {
		return report, err
	}
	if input != p.Root || plan != p.Plan || dev != p.Device || inode != p.Inode {
		return report, errors.New("key cleanup root identity mismatch")
	}
	now := clock()
	if now.UnixNano() < int64(p.Created) {
		return report, errors.New("key cleanup clock regression")
	}
	report = backupKeysReclaimReport(p.Bundle, now)
	raw, err = readPrivate(filepath.Join(input, "bundle.json"), backupKeysLimit)
	if err != nil && !(report.Expired && errors.Is(err, os.ErrNotExist)) {
		return report, err
	}
	if err == nil && sha256.Sum256(raw) != p.BundleSHA {
		return report, errors.New("key cleanup bundle binding mismatch")
	}
	files, dirs := backupKeysInventory()
	if err = walkBackupInventory(ctx, input, files, dirs, report.Expired); err != nil {
		return report, err
	}
	if !report.Expired || !apply {
		return report, nil
	}
	if err = privatePath(filepath.Dir(plan), true); err != nil {
		return report, err
	}
	finish := func(stage string) error {
		if e := boundary(stage); e != nil {
			return e
		}
		if stage == "backup:reclaim_manifest" {
			if e := ctx.Err(); e != nil {
				return e
			}
			if e := retireBackupKeysPlan(plan, planRaw); e != nil {
				return e
			}
			return boundary("backup:keys_plan_retired")
		}
		return nil
	}
	if err = reclaimBackupInventoryWithMissingManifest(ctx, input, files, dirs, "bundle.json", true, finish); err != nil {
		return report, err
	}
	report.Applied = true
	return report, nil
}

// retireBackupKeysPlan はrootを消す前に使用済み印をatomic renameと親Syncで保存する。
// 途中の.pendingを上書きしない。使用済み後にrootが残れば所有者が空rootを確認して扱う。
func retireBackupKeysPlan(path string, original []byte) error {
	return retireBackupCleanupPlan(path, original, backupKeysPlanLimit)
}

// retireBackupCleanupPlan は用途別署名を検証済みの共通envelopeを使用済みへ同期する。
func retireBackupCleanupPlan(path string, original []byte, limit int64) error {
	if e := privatePath(filepath.Dir(path), true); e != nil {
		return e
	}
	current, e := readPrivate(path, limit)
	if e != nil {
		return e
	}
	if sha256.Sum256(current) != sha256.Sum256(original) {
		return errors.New("backup cleanup plan changed during reclamation")
	}
	var env backupKeysPlanEnvelope
	if e = strictjson.Decode(current, &env); e != nil {
		return e
	}
	env.Retired = true
	raw, e := json.Marshal(env)
	if e != nil {
		return e
	}
	pending := path + backupKeysRetireSuffix
	if e = writeNew(pending, raw); e != nil {
		return e
	}
	if e = store.SyncDirectory(filepath.Dir(path)); e != nil {
		return e
	}
	if e = os.Rename(pending, path); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(path))
}
