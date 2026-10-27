// 正本・バックアップ鍵の喪失後も、事前に独立認証した検証コピーだけを回収する。
package bootstrap

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
)

const independentReplayGate = "backup-replay-independent.json"

// validateIndependentCleanupPaths は本文/鍵束/作業/制御領域への同梱を拒否し、鍵を検証する。
func validateIndependentCleanupPaths(keyPath string, paths ...string) error {
	for _, path := range paths {
		if e := separateBackupPaths(path, keyPath); e != nil {
			return e
		}
	}
	key, e := independentReplayKey(keyPath)
	clear(key[:])
	return e
}

// InitializeReplayCleanupKey は独立した0600の回収鍵を新規作成し、親へ同期する。
// 既存鍵を上書きしない。鍵は公開復元・投稿署名・バックアップ認証には使用しない。
func InitializeReplayCleanupKey(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("absolute canonical cleanup key path required")
	}
	if e := privatePath(filepath.Dir(path), true); e != nil {
		return e
	}
	raw := make([]byte, 32)
	defer clear(raw)
	if _, e := rand.Read(raw); e != nil {
		return e
	}
	if e := writeNew(path, raw); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(path))
}

// independentReplayKey は保存された独立鍵から回収だけの用途鍵を導出する。
func independentReplayKey(path string) (domain.Hash, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return domain.Hash{}, errors.New("absolute canonical cleanup key path required")
	}
	if e := privatePath(filepath.Dir(path), true); e != nil {
		return domain.Hash{}, e
	}
	raw, e := readPrivate(path, 32)
	if e != nil {
		return domain.Hash{}, e
	}
	defer clear(raw)
	if len(raw) != 32 {
		return domain.Hash{}, errors.New("cleanup key must contain exactly 32 bytes")
	}
	return identity.DeriveKey(raw, "independent_replay_cleanup", 1)
}

// writeIndependentReplayPlan は既存の認証済み計画を別用途鍵へ束縛して同期する。
func writeIndependentReplayPlan(root, path string, plan replayCleanupPlan) error {
	if e := separateBackupPaths(root, path); e != nil {
		return e
	}
	key, e := independentReplayKey(path)
	if e != nil {
		return e
	}
	defer clear(key[:])
	raw, e := encodeReplayCleanupPlan(plan, key)
	if e != nil {
		return e
	}
	if e = writeNew(filepath.Join(root, independentReplayGate), raw); e != nil {
		return e
	}
	return errors.Join(store.SyncDirectory(root), store.SyncDirectory(filepath.Dir(root)))
}

// VerifyBackupReplayWithCleanupKey は独立回収の認証印を複写前に保存して隔離再生する。
// cleanupKeyは本文・鍵bundle・作業親と別の領域に事前作成し、喪失後の回収まで保持する。
func VerifyBackupReplayWithCleanupKey(ctx context.Context, input, keys, parent, cleanupKey string) (report BackupReport, err error) {
	for _, p := range []string{input, keys, parent} {
		if err = separateBackupPaths(p, cleanupKey); err != nil {
			return report, err
		}
	}
	key, err := independentReplayKey(cleanupKey)
	if err != nil {
		return report, err
	}
	clear(key[:])
	unlock, err := lockBackupDirectories(filepath.Dir(input), filepath.Dir(keys), parent)
	if err != nil {
		return report, err
	}
	defer func() {
		err = errors.Join(err, unlock())
		if err != nil {
			report.Verified, report.Replayed = false, false
		}
	}()
	return verifyBackupReplayIndependent(ctx, input, keys, parent, cleanupKey, time.Now, func(string) error { return nil })
}

// ReclaimBackupReplayWithCleanupKey は本文・別保管鍵・正本を使わず停止領域を認証回収する。
// 事前認証印、元path/device/inode、同じlockと限定配置が必要。旧領域を推測認証しない。
func ReclaimBackupReplayWithCleanupKey(ctx context.Context, root, cleanupKey string, apply bool) (ReplayReclaimReport, error) {
	return reclaimIndependentReplay(ctx, root, cleanupKey, apply, func(string) error { return nil })
}

// reclaimIndependentReplay は認証印を全payload除去まで保持し、取消後も同じ鍵で再開する。
func reclaimIndependentReplay(ctx context.Context, root, cleanupKey string, apply bool, boundary func(string) error) (report ReplayReclaimReport, err error) {
	if err = separateBackupPaths(root, cleanupKey); err != nil {
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
			err = errors.Join(errReplayRootBusy, err)
		}
		return report, err
	}
	defer func() {
		err = errors.Join(err, platform.Unlock(lock))
		if err != nil {
			report.Applied = false
		}
	}()
	key, err := independentReplayKey(cleanupKey)
	if err != nil {
		return report, err
	}
	defer clear(key[:])
	raw, err := readPrivate(filepath.Join(root, independentReplayGate), replayCleanupLimit)
	if err != nil {
		return report, err
	}
	plan, err := decodeReplayCleanupPlan(raw, key)
	if err != nil {
		return report, err
	}
	dev, inode, err := replayRootIdentity(root)
	if err != nil {
		return report, err
	}
	if plan.Root != root || plan.Device != dev || plan.Inode != inode {
		return report, errors.New("independent cleanup root binding mismatch")
	}
	files, dirs, err := replayCleanupInventory(plan)
	if err != nil {
		return report, err
	}
	if err = walkBackupInventory(ctx, root, files, dirs, true); err != nil {
		return report, err
	}
	report.BackupID, report.PlannedFiles = plan.Backup.ID, len(files)-3
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

// SweepBackupReplayWithCleanupKey は鍵束を失った停止領域を最大limit件ずつ巡回する。
// 不正・未知領域を保持し、busyも次巡回へ残す。公開復元を許可しない。
func SweepBackupReplayWithCleanupKey(ctx context.Context, parent, cleanupKey, after string, limit int, apply bool) (report ReplaySweepReport, err error) {
	report.Items = []ReplaySweepItem{}
	report.Next = after
	if limit < 1 || limit > 128 || after != "" && !validReplaySweepName(after) {
		return report, errors.New("invalid independent replay cursor or limit")
	}
	if err = separateBackupPaths(parent, cleanupKey); err != nil {
		return report, err
	}
	if err = privatePath(parent, true); err != nil {
		return report, err
	}
	key, err := independentReplayKey(cleanupKey)
	if err != nil {
		return report, err
	}
	clear(key[:])
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
		item := ReplaySweepItem{Name: name, Status: "rejected"}
		root := filepath.Join(parent, name)
		reclaimed, e := ReclaimBackupReplayWithCleanupKey(ctx, root, cleanupKey, apply)
		if ctx.Err() != nil {
			report.More = true
			return report, ctx.Err()
		}
		switch {
		case errors.Is(e, errReplayRootBusy):
			item.Status = "busy"
			report.Busy++
		case e == nil:
			item.Status, item.Reclaim = "verified", &reclaimed
			if reclaimed.Applied {
				item.Status = "reclaimed"
			}
		case errors.Is(e, os.ErrNotExist):
			if _, statErr := os.Lstat(root); errors.Is(statErr, os.ErrNotExist) {
				item.Status = "gone"
			} else {
				report.Rejected++
			}
		default:
			report.Rejected++
		}
		report.Items = append(report.Items, item)
		report.Next = name
	}
	if report.Rejected > 0 {
		return report, ErrReplaySweepRejected
	}
	return report, nil
}
