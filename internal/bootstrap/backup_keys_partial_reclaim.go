// 外部公開信頼根と事前署名計画だけで、完成印のない期限切れ鍵束を認証回収する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// ReclaimPartialBackupKeys は未完成鍵束の認証回収。正本と鍵束内の秘密鍵は読まない。
// 欠落/短いfileを許すが、完成印・未知file・予定長超過を拒否する。apply時も期限切れだけ。
func ReclaimPartialBackupKeys(ctx context.Context, input, trust, plan string, apply bool) (BackupReport, error) {
	return reclaimPartialBackupKeys(ctx, input, trust, plan, apply, time.Now, func(string) error { return nil })
}

func reclaimPartialBackupKeys(ctx context.Context, input, trust, plan string, apply bool, clock func() time.Time, boundary func(string) error) (report BackupReport, err error) {
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
	p, err := decodePartialKeysPlan(raw, marker, trustRaw)
	if err != nil {
		return report, err
	}
	dev, inode, err := replayRootIdentity(input)
	if err != nil {
		return report, err
	}
	if input != p.Root || plan != p.Plan || dev != p.Device || inode != p.Inode {
		return report, errors.New("partial key cleanup root identity mismatch")
	}
	now := clock()
	if now.UnixNano() < int64(p.Bundle.Created) {
		return report, errors.New("partial key cleanup clock regression")
	}
	report = backupKeysReclaimReport(p.Bundle, now)
	files, dirs := backupKeysInventory()
	delete(files, "bundle.json")
	files["bundle.pending"] = true
	if err = walkBackupInventory(ctx, input, files, dirs, true); err != nil {
		return report, err
	}
	if err = validatePartialKeysLengths(ctx, input, p); err != nil {
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
			if e := retireBackupCleanupPlan(plan, raw, backupKeysPlanLimit); e != nil {
				return e
			}
			return boundary("backup:partial_keys_plan_retired")
		}
		return nil
	}
	if err = reclaimBackupInventoryWithMissingManifest(ctx, input, files, dirs, "bundle.pending", true, finish); err != nil {
		return report, err
	}
	report.Applied = true
	return report, nil
}

// validatePartialKeysLengths は全予定fileの上限と、完成長pendingの指紋だけを照合する。
func validatePartialKeysLengths(ctx context.Context, root string, p backupPartialKeysPlan) error {
	for _, f := range p.Bundle.Files {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := partialBackupLength(filepath.Join(root, filepath.FromSlash(f.Name)), f.Length); e != nil {
			return e
		}
	}
	pending := filepath.Join(root, "bundle.pending")
	if e := partialBackupLength(pending, p.BundleBytes); e != nil {
		return e
	}
	raw, e := readPrivate(pending, backupKeysLimit)
	if errors.Is(e, os.ErrNotExist) {
		return ctx.Err()
	}
	if e != nil {
		return e
	}
	if uint64(len(raw)) == uint64(p.BundleBytes) && sha256.Sum256(raw) != p.BundleSHA {
		return errors.New("partial key pending bundle mismatch")
	}
	return ctx.Err()
}
