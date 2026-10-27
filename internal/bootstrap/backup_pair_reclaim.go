// 外部公開信頼根と完成ペア計画だけで本文を先に回収し、鍵束を最後に回収する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
)

// ReclaimBackupPair は正本・config・生鍵を読まず、署名計画に対応する期限切れ完成ペアを回収する。
// 本文root除去前に本文使用済み印、鍵root除去前に全体使用済み印を同期する。
// 印の同期後に空rootが残る中断だけは所有者の確認を必要とし、自動で同名rootを再利用しない。
func ReclaimBackupPair(ctx context.Context, body, keys, trust, plan string, apply bool) (BackupPairReport, error) {
	return reclaimBackupPair(ctx, body, keys, trust, plan, apply, time.Now, func(string) error { return nil })
}

func reclaimBackupPair(ctx context.Context, body, keys, trust, plan string, apply bool, clock func() time.Time, boundary func(string) error) (report BackupPairReport, err error) {
	report.Phase = "preflight"
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = backupPairPaths(body, keys, trust, plan); err != nil {
		return report, err
	}
	unlock, err := lockBackupPairParents(body, keys)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	return reclaimBackupPairLocked(ctx, body, keys, trust, plan, apply, clock, boundary)
}

// reclaimBackupPairLocked は両出力親を呼出元が排他している場合の単発/巡回共通処理。
func reclaimBackupPairLocked(ctx context.Context, body, keys, trust, plan string, apply bool, clock func() time.Time, boundary func(string) error) (report BackupPairReport, err error) {
	report.Phase = "preflight"
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = backupPairPaths(body, keys, trust, plan); err != nil {
		return report, err
	}
	marker, trustRaw, err := loadBackupTrust(trust)
	if err != nil {
		return report, err
	}
	raw, err := readPrivate(plan, backupPairPlanLimit)
	if err != nil {
		return report, err
	}
	p, refs, env, err := decodeBackupPairPlanRelated(raw, marker, trustRaw)
	if err != nil {
		return report, err
	}
	if p.Body.Root != body || p.Keys.Root != keys || p.Body.Plan != plan {
		return report, errors.New("pair cleanup path binding mismatch")
	}
	now := clock()
	if now.UnixNano() < int64(p.Keys.Created) {
		return report, errors.New("pair cleanup clock regression")
	}
	br, err := validateBackupManifest(p.Body.Manifest)
	if err != nil {
		return report, err
	}
	kr := backupKeysReclaimReport(p.Keys.Bundle, now)
	br.Expired = kr.Expired
	report.Body = &br
	report.Keys = &kr
	report.Expired = kr.Expired
	if err = validateBackupPairRoot(ctx, keys, p.Keys.Device, p.Keys.Inode, "bundle.json", p.Keys.BundleSHA, backupKeysLimit, kr.Expired, false, backupKeysInventory); err != nil {
		return report, err
	}
	bodyInventory := func() (map[string]bool, map[string]bool) { return backupInventory(p.Body.Manifest, true) }
	if err = validateBackupPairRoot(ctx, body, p.Body.Device, p.Body.Inode, "manifest.json", p.Body.ManifestSHA, backupManifestLimit, kr.Expired, env.BodyRetired, bodyInventory); err != nil {
		return report, err
	}
	states, err := loadPairRelatedPlans(ctx, p, refs, marker, trustRaw, trust, true)
	if err != nil {
		return report, err
	}
	if len(refs) > 0 {
		count := len(refs)
		retired := 0
		for _, state := range states {
			if state.retired {
				retired++
			}
		}
		report.RelatedPlanCount = &count
		report.RelatedRetiredCount = &retired
	}
	report.BodyRemoved = env.BodyRetired
	if !apply || !report.Expired {
		report.Phase = "retained"
		return report, nil
	}
	if err = privatePath(filepath.Dir(plan), true); err != nil {
		return report, err
	}
	if len(refs) > 0 {
		report.Phase = "related_plans"
		if err = retirePairRelatedPlans(ctx, states, &report, boundary); err != nil {
			return report, err
		}
	}
	if !env.BodyRetired {
		report.Phase = "body"
		files, dirs := bodyInventory()
		finish := func(stage string) error {
			if e := boundary("body:" + stage); e != nil {
				return e
			}
			if stage != "backup:reclaim_manifest" {
				return nil
			}
			if e := ctx.Err(); e != nil {
				return e
			}
			if e := requirePairRelatedRetired(ctx, p, refs, marker, trustRaw, trust, &report); e != nil {
				return e
			}
			env.BodyRetired = true
			updated, e := saveBackupPairState(plan, raw, env)
			if e != nil {
				return e
			}
			raw = updated
			return boundary("pair:body_retired")
		}
		if err = reclaimBackupInventoryWithMissingManifest(ctx, body, files, dirs, "manifest.json", true, finish); err != nil {
			return report, err
		}
		report.BodyRemoved = true
		br.Applied = true
		if err = boundary("pair:body_removed"); err != nil {
			return report, err
		}
	}
	// 使用済み本文pathに何か再配置されていたら鍵を保持する。
	if _, e := os.Lstat(body); !errors.Is(e, os.ErrNotExist) {
		return report, errors.New("body root must remain absent before key reclamation")
	}
	if err = validateBackupPairRoot(ctx, keys, p.Keys.Device, p.Keys.Inode, "bundle.json", p.Keys.BundleSHA, backupKeysLimit, true, false, backupKeysInventory); err != nil {
		return report, err
	}
	if err = requirePairRelatedRetired(ctx, p, refs, marker, trustRaw, trust, &report); err != nil {
		return report, err
	}
	report.Phase = "keys"
	files, dirs := backupKeysInventory()
	finish := func(stage string) error {
		if e := boundary("keys:" + stage); e != nil {
			return e
		}
		if stage != "backup:reclaim_manifest" {
			return nil
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := requirePairRelatedRetired(ctx, p, refs, marker, trustRaw, trust, &report); e != nil {
			return e
		}
		env.Retired = true
		if _, e := saveBackupPairState(plan, raw, env); e != nil {
			return e
		}
		return boundary("pair:retired")
	}
	if err = reclaimBackupInventoryWithMissingManifest(ctx, keys, files, dirs, "bundle.json", true, finish); err != nil {
		return report, err
	}
	kr.Applied = true
	report.KeysRemoved = true
	report.Applied = true
	report.Phase = "complete"
	return report, nil
}

// validateBackupPairRoot は欠落再開を期限切れだけに許し、使用済み本文は不在だけを許す。
func validateBackupPairRoot(ctx context.Context, root string, dev, inode domain.U64, manifest string, hash domain.Hash, limit int64, expired, retired bool, inventory func() (map[string]bool, map[string]bool)) error {
	if retired {
		if _, e := os.Lstat(root); errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return errors.New("retired body root remains; inspect empty root before resuming")
	}
	d, i, e := replayRootIdentity(root)
	if e != nil {
		return e
	}
	if d != dev || i != inode {
		return errors.New("pair cleanup root identity mismatch")
	}
	raw, e := readPrivate(filepath.Join(root, manifest), limit)
	if e != nil && !(expired && errors.Is(e, os.ErrNotExist)) {
		return e
	}
	if e == nil && sha256.Sum256(raw) != hash {
		return errors.New("pair cleanup manifest binding mismatch")
	}
	files, dirs := inventory()
	return walkBackupInventory(ctx, root, files, dirs, expired)
}

// saveBackupPairState は認証済み計画の停止印を元bytes照合と新規file/rename/親Syncで保存する。
// 途中.pendingは上書きせず停止する。停止印の巻戻しは許可しない。
func saveBackupPairState(path string, original []byte, env backupPairEnvelope) ([]byte, error) {
	current, e := readPrivate(path, backupPairPlanLimit)
	if e != nil {
		return nil, e
	}
	if sha256.Sum256(current) != sha256.Sum256(original) {
		return nil, errors.New("pair plan changed during reclamation")
	}
	raw, e := json.Marshal(env)
	if e != nil {
		return nil, e
	}
	pending := path + backupKeysRetireSuffix
	if e = writeNew(pending, raw); e != nil {
		return nil, e
	}
	if e = store.SyncDirectory(filepath.Dir(path)); e != nil {
		return nil, e
	}
	if e = os.Rename(pending, path); e != nil {
		return nil, e
	}
	if e = store.SyncDirectory(filepath.Dir(path)); e != nil {
		return nil, e
	}
	return raw, nil
}

// lockBackupPairParents は共有親を一度だけ、異なる親はpath順で非待機排他する。
// watch/sweepと同じ.lockを使い、失敗時は取得済み排他をすべて解放する。
func lockBackupPairParents(body, keys string) (func() error, error) {
	return lockBackupDirectories(filepath.Dir(body), filepath.Dir(keys))
}

// lockBackupDirectories は指定した所有者限定親を重複なくpath順に非待機排他する。
func lockBackupDirectories(dirs ...string) (func() error, error) {
	parents := append([]string{}, dirs...)
	slices.Sort(parents)
	parents = slices.Compact(parents)
	locks := []*os.File{}
	unlock := func() (err error) {
		for i := len(locks) - 1; i >= 0; i-- {
			err = errors.Join(err, platform.Unlock(locks[i]))
		}
		return err
	}
	for _, parent := range parents {
		if e := privatePath(parent, true); e != nil {
			return nil, errors.Join(e, unlock())
		}
		lock, e := platform.Lock(parent)
		if e != nil {
			return nil, errors.Join(e, unlock())
		}
		locks = append(locks, lock)
	}
	return unlock, nil
}
