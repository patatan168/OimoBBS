// 認証済みmanifestが失効したコピーだけを回収し、中断後も欠落済みファイルを許容して再開する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"oimobbs/internal/store"
)

// ReclaimOfflineBackup は期限切れコピーを列挙し、apply時だけ回収する。
// 未列挙ファイル・リンクは拒否する。正本・期限内コピー・未完成出力は削除しない。
func ReclaimOfflineBackup(ctx context.Context, cfg Config, input string, apply bool) (BackupReport, error) {
	return reclaimOfflineBackup(ctx, cfg, input, apply, time.Now, func(string) error { return nil })
}
func reclaimOfflineBackup(ctx context.Context, cfg Config, input string, apply bool, clock func() time.Time, boundary func(string) error) (report BackupReport, err error) {
	r, err := openBackupRepository(cfg)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	m, report, err := r.loadBackup(input)
	if err != nil {
		return report, err
	}
	if clock().UnixNano() < int64(m.Created) {
		return report, errors.New("backup reclamation clock regression")
	}
	report.Expired = clock().UnixNano() >= int64(m.Expires)
	files, dirs := backupInventory(m, true)
	if err = walkBackupInventory(ctx, input, files, dirs, report.Expired); err != nil {
		return report, err
	}
	if !report.Expired || !apply {
		return report, nil
	}
	if err = reclaimBackupInventory(ctx, input, files, dirs, "manifest.json", boundary); err != nil {
		return report, err
	}
	report.Applied = true
	return report, nil
}

// reclaimBackupInventory は認証済み集合だけを消し、再開に必要なmanifestを最後まで残す。
func reclaimBackupInventory(ctx context.Context, input string, files, dirs map[string]bool, manifest string, boundary func(string) error) error {
	return reclaimBackupInventoryWithMissingManifest(ctx, input, files, dirs, manifest, false, boundary)
}

// reclaimBackupInventoryWithMissingManifest は外部認証計画がある場合だけ完成印欠落から再開する。
func reclaimBackupInventoryWithMissingManifest(ctx context.Context, input string, files, dirs map[string]bool, manifest string, allowMissing bool, boundary func(string) error) error {
	var err error
	names := make([]string, 0, len(files))
	for name := range files {
		if name != manifest {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		if err = ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(input, filepath.FromSlash(name))
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if _, e := os.Stat(filepath.Dir(path)); e == nil {
			if err = store.SyncDirectory(filepath.Dir(path)); err != nil {
				return err
			}
		}
		if err = boundary("backup:reclaim_file"); err != nil {
			return err
		}
	}
	if err = removeBackupDirectories(input, dirs); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(input, manifest)); err != nil && !(allowMissing && errors.Is(err, os.ErrNotExist)) {
		return err
	}
	if err = store.SyncDirectory(input); err != nil {
		return err
	}
	if allowMissing {
		if err = boundary("backup:reclaim_manifest"); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
	}
	if err = os.Remove(input); err != nil {
		return err
	}
	if err = store.SyncDirectory(filepath.Dir(input)); err != nil {
		return err
	}
	return nil
}

func removeBackupDirectories(root string, dirs map[string]bool) error {
	names := make([]string, 0, len(dirs))
	for dir := range dirs {
		if dir != "." {
			names = append(names, dir)
		}
	}
	slices.SortFunc(names, func(a, b string) int { return backupDirectoryDepth(b) - backupDirectoryDepth(a) })
	for _, name := range names {
		path := filepath.Join(root, filepath.FromSlash(name))
		if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if _, e := os.Stat(filepath.Dir(path)); e == nil {
			if e = store.SyncDirectory(filepath.Dir(path)); e != nil {
				return e
			}
		}
	}
	return nil
}
