// 外部署名計画だけで未完成コピーを検査し、期限切れに限定して中断再開可能な回収を行う。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
)

// ReclaimPartialBackup は完成印のない計画付きコピーだけを認証し、期限切れapplyで回収する。
// 正本・別保管秘密鍵を読まず、欠落/途中長のpayloadを許す。全payloadのhash照合はしない。
// root除去前に計画を使用済み化する。使用済み後の残存rootは手動確認へ残す。
func ReclaimPartialBackup(ctx context.Context, input, trust, plan string, apply bool) (BackupReport, error) {
	return reclaimPartialBackup(ctx, input, trust, plan, apply, time.Now, func(string) error { return nil })
}

func reclaimPartialBackup(ctx context.Context, input, trust, plan string, apply bool, clock func() time.Time, boundary func(string) error) (report BackupReport, err error) {
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
	raw, err := readPrivate(plan, backupPartialPlanLimit)
	if err != nil {
		return report, err
	}
	p, err := decodeBackupPartialPlan(raw, marker, trustRaw)
	if err != nil {
		return report, err
	}
	dev, inode, err := replayRootIdentity(input)
	if err != nil {
		return report, err
	}
	if input != p.Root || plan != p.Plan || dev != p.Device || inode != p.Inode {
		return report, errors.New("partial cleanup root identity mismatch")
	}
	now := clock()
	if now.UnixNano() < int64(p.Manifest.Created) {
		return report, errors.New("partial cleanup clock regression")
	}
	report, err = validateBackupManifest(p.Manifest)
	if err != nil {
		return report, err
	}
	report.Expired = now.UnixNano() >= int64(p.Manifest.Expires)
	files, dirs := backupInventory(p.Manifest, false)
	files["manifest.pending"] = true
	// 完成印が存在するコピーは未知fileとして拒否し、従来の完成コピー回収へ委ねる。
	if err = walkBackupInventory(ctx, input, files, dirs, true); err != nil {
		return report, err
	}
	if err = validatePartialBackupLengths(ctx, input, p); err != nil {
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
			if e := retireBackupCleanupPlan(plan, raw, backupPartialPlanLimit); e != nil {
				return e
			}
			return boundary("backup:partial_plan_retired")
		}
		return nil
	}
	if err = reclaimBackupInventoryWithMissingManifest(ctx, input, files, dirs, "manifest.pending", true, finish); err != nil {
		return report, err
	}
	report.Applied = true
	return report, nil
}

// validatePartialBackupLengths は予定より長いfileを拒否し、完成長のpendingだけhashを照合する。
// 欠落や短いpayloadはコピー中断として扱うが、内容検証済みとは報告しない。
func validatePartialBackupLengths(ctx context.Context, root string, p backupPartialCleanupPlan) error {
	for _, entry := range p.Manifest.Entries {
		for _, file := range entry.Files {
			if e := ctx.Err(); e != nil {
				return e
			}
			if e := partialBackupLength(filepath.Join(root, filepath.FromSlash(backupEntryPath(entry)+"/"+file.Name)), file.Length); e != nil {
				return e
			}
		}
	}
	pending := filepath.Join(root, "manifest.pending")
	if e := partialBackupLength(pending, p.ManifestBytes); e != nil {
		return e
	}
	raw, e := readPrivate(pending, backupManifestLimit)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if uint64(len(raw)) == uint64(p.ManifestBytes) && sha256.Sum256(raw) != p.ManifestSHA {
		return errors.New("partial cleanup pending manifest mismatch")
	}
	return ctx.Err()
}

// partialBackupLength は欠落を許し、通常fileの予定長上限とprivate属性を再確認する。
func partialBackupLength(path string, maximum domain.U64) error {
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = privatePath(path, false); e != nil {
		return e
	}
	if info.Size() < 0 || uint64(info.Size()) > uint64(maximum) {
		return errors.New("partial cleanup file exceeds planned length")
	}
	return nil
}
