// 別保管鍵と残存lockで停止済みの再生領域だけを認証し、列挙済みファイルを回収する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
)

var errReplayRootBusy = errors.New("replay root is active")

// ReplayReclaimReport は認証済み回収計画の結果。本文・生鍵・公開復元許可を返さない。
type ReplayReclaimReport struct {
	BackupID     domain.ID `json:"backup_id"`
	PlannedFiles int       `json:"planned_file_count"`
	Applied      bool      `json:"applied"`
	RestoreReady bool      `json:"restore_ready"`
}

// ReclaimBackupReplay は正本不要で停止済みの作業rootを照合し、apply時だけ回収する。
// 欠落済みpayloadは許容し、別位置・未列挙・リンク・稼働中・認証されない旧印は拒否する。
func ReclaimBackupReplay(ctx context.Context, root, keys string, apply bool) (ReplayReclaimReport, error) {
	return reclaimBackupReplay(ctx, root, keys, apply, func(string) error { return nil })
}
func reclaimBackupReplay(ctx context.Context, root, keys string, apply bool, boundary func(string) error) (report ReplayReclaimReport, err error) {
	if err = separateBackupPaths(root, keys); err != nil {
		return report, err
	}
	if err = privatePath(filepath.Dir(root), true); err != nil {
		return report, err
	}
	if err = privatePath(root, true); err != nil {
		return report, err
	}
	if err = privatePath(filepath.Join(root, ".lock"), false); err != nil {
		return report, err
	}
	lock, err := platform.Lock(root)
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return report, errors.Join(errReplayRootBusy, err)
		}
		return report, err
	}
	defer func() {
		err = errors.Join(err, platform.Unlock(lock))
		if err != nil {
			report.Applied = false
		}
	}()
	bundle, err := loadBackupKeys(ctx, keys)
	if err != nil {
		return report, err
	}
	key, err := replayCleanupKey(keys)
	if err != nil {
		return report, err
	}
	defer clear(key[:])
	raw, err := readPrivate(filepath.Join(root, backupReplayGate), replayCleanupLimit)
	if err != nil {
		return report, err
	}
	p, err := decodeReplayCleanupPlan(raw, key)
	if err != nil {
		return report, err
	}
	dev, inode, err := replayRootIdentity(root)
	if err != nil {
		return report, err
	}
	if p.Root != root || p.Device != dev || p.Inode != inode || p.Backup.ID != bundle.Backup || p.Backup.Site != bundle.Site || p.BackupSHA != bundle.BackupSHA || p.Backup.Expires != bundle.Expires {
		return report, errors.New("replay cleanup plan binding mismatch")
	}
	files, dirs, err := replayCleanupInventory(p)
	if err != nil {
		return report, err
	}
	if err = walkBackupInventory(ctx, root, files, dirs, true); err != nil {
		return report, err
	}
	report = ReplayReclaimReport{BackupID: p.Backup.ID, PlannedFiles: len(files) - 3}
	if !apply {
		return report, nil
	}
	if err = removeReplayPayloads(ctx, root, files, dirs, boundary); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = finishReplayCleanup(root); err != nil {
		return report, err
	}

	report.Applied = true
	return report, nil
}
func removeReplayPayloads(ctx context.Context, root string, files, dirs map[string]bool, boundary func(string) error) error {
	names := []string{}
	for name := range files {
		if name != backupReplayGate && name != independentReplayGate && name != ".lock" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		if e := ctx.Err(); e != nil {
			return e
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if _, e := os.Stat(filepath.Dir(path)); e == nil {
			if e = store.SyncDirectory(filepath.Dir(path)); e != nil {
				return e
			}
		}
		if e := boundary("replay-cleanup:file"); e != nil {
			return e
		}
	}
	return removeBackupDirectories(root, dirs)
}

// cleanupOwnedReplayRoot は実行中に認証した計画を使い、後片付け中も回収境界を維持する。
func cleanupOwnedReplayRoot(root string, p replayCleanupPlan, boundary func(string) error) error {
	dev, inode, e := replayRootIdentity(root)
	if e != nil {
		return e
	}
	if p.Root != root || p.Device != dev || p.Inode != inode {
		return errors.New("owned replay root identity changed")
	}
	files, dirs, e := replayCleanupInventory(p)
	if e != nil {
		return e
	}
	if e = walkBackupInventory(context.Background(), root, files, dirs, true); e != nil {
		return e
	}
	if e = removeReplayPayloads(context.Background(), root, files, dirs, boundary); e != nil {
		return e
	}
	return finishReplayCleanup(root)
}

// finishReplayCleanup は全payload除去後にだけ、認証印・lock・空rootを除去し同期する。
func finishReplayCleanup(root string) error {
	for _, name := range []string{backupReplayGate, ".lock"} {
		if name == ".lock" {
			if e := os.Remove(filepath.Join(root, independentReplayGate)); e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
			if e := store.SyncDirectory(root); e != nil {
				return e
			}
		}
		if e := os.Remove(filepath.Join(root, name)); e != nil && !(name == backupReplayGate && errors.Is(e, os.ErrNotExist)) {
			return e
		}
		if e := store.SyncDirectory(root); e != nil {
			return e
		}
	}
	if e := os.Remove(root); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(root))
}
