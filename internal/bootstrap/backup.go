// 停止中バックアップを新規の管理領域へ保存し、最後の認証manifestを完成印にする。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

// CaptureOfflineBackup は停止中の全投稿・制御・署名記録を照合してコピーする。
// 生鍵・予約領域・旧保存世代・非必須HTTPログ本文は含めない。HTTPログの除外は署名説明と結果へ明示する。
// 未完成の出力は消さず、同じ出力を再利用しない。
func CaptureOfflineBackup(ctx context.Context, cfg Config, output string) (BackupReport, error) {
	return captureOfflineBackup(ctx, cfg, output, time.Now, func(string) {})
}
func captureOfflineBackup(ctx context.Context, cfg Config, output string, clock func() time.Time, boundary func(string)) (result BackupReport, err error) {
	r, err := openBackupRepository(cfg)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	return r.captureOfflineBackup(ctx, output, clock, boundary)
}

// captureOfflineBackup は既に排他を保持する停止中Repositoryからコピーを作成する。
func (r *Repository) captureOfflineBackup(ctx context.Context, output string, clock func() time.Time, boundary func(string)) (result BackupReport, err error) {
	return r.captureOfflineBackupWithSetup(ctx, output, clock, boundary, func(backupManifest, []byte) error { return nil })
}

// captureOfflineBackupWithSetup はroot同期後、payloadを書込む前に外部回収計画を保存できる。
func (r *Repository) captureOfflineBackupWithSetup(ctx context.Context, output string, clock func() time.Time, boundary func(string), setup func(backupManifest, []byte) error) (result BackupReport, err error) {
	cfg := r.cfg
	if err = r.candidatePath(output); err != nil {
		return result, err
	}
	if _, err = checkLockedPosting(cfg, false, true); err != nil {
		return result, err
	}
	plan, err := r.planOfflineBackup(ctx, clock)
	if err != nil {
		return result, err
	}
	result, err = validateBackupManifest(plan.manifest)
	if err != nil {
		return result, err
	}
	key, err := backupKey(cfg.DataDir)
	if err != nil {
		return result, err
	}
	defer clear(key[:])
	raw, err := encodeBackupManifest(plan.manifest, key)
	if err != nil {
		return result, err
	}
	if err = backupCapacity(cfg.DataDir, filepath.Dir(output), uint64(result.Bytes)+uint64(len(raw))); err != nil {
		return result, err
	}
	if err = os.Mkdir(output, 0700); err != nil {
		return result, err
	}
	if err = store.SyncDirectory(filepath.Dir(output)); err != nil {
		return result, err
	}
	boundary("backup:directory")
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = setup(plan.manifest, raw); err != nil {
		return result, err
	}
	for _, source := range plan.sources {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		if clock().UnixNano() >= int64(plan.manifest.Expires) {
			return result, errors.New("backup expired during capture")
		}
		if err = backupCapacity(cfg.DataDir, output, uint64(source.file.Length)); err != nil {
			return result, err
		}
		if err = writeBackupSource(ctx, output, source); err != nil {
			return result, err
		}
		boundary("backup:file")
	}
	if err = verifyBackupFiles(ctx, output, plan.manifest, false); err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if clock().UnixNano() >= int64(plan.manifest.Expires) {
		return result, errors.New("backup expired before completion")
	}
	if err = backupCapacity(cfg.DataDir, output, uint64(len(raw))); err != nil {
		return result, err
	}

	if err = writeNew(filepath.Join(output, "manifest.pending"), raw); err != nil {
		return result, err
	}
	boundary("backup:manifest_synced")
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if clock().UnixNano() >= int64(plan.manifest.Expires) {
		return result, errors.New("backup expired before manifest installation")
	}
	if err = os.Rename(filepath.Join(output, "manifest.pending"), filepath.Join(output, "manifest.json")); err != nil {
		return result, err
	}
	if err = store.SyncDirectory(output); err != nil {
		return result, err
	}
	if err = store.SyncDirectory(filepath.Dir(output)); err != nil {
		return result, err
	}
	boundary("backup:complete")
	result.Verified = true
	return result, nil
}

func backupCapacity(source, target string, bytes uint64) error {
	reserve, e := inspectEmergencyReserve(source)
	if e != nil || reserve.Enabled && !reserve.Ready {
		return errors.New("emergency reserve requires recovery before backup")
	}
	space, e := platform.Space(target)
	if e != nil {
		return e
	}
	floor := max(uint64(1<<30), space.Total/10)
	if bytes > backupByteLimit+backupManifestLimit || space.Available < floor || space.Available-floor < bytes+(16<<20) {
		return errors.New("insufficient capacity for backup")
	}
	return nil
}

type backupReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r backupReader) Read(buf []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.reader.Read(buf)
}

func writeBackupSource(ctx context.Context, root string, source backupSource) error {
	target := filepath.Join(root, filepath.FromSlash(source.target))
	if e := makeBackupDirectories(root, filepath.Dir(target)); e != nil {
		return e
	}
	if source.generated != nil {
		return writeNew(target, source.generated)
	}
	if e := privatePath(source.source, false); e != nil {
		return e
	}
	input, e := os.OpenFile(source.source, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer input.Close()
	output, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	hash := sha256.New()
	n, copyErr := io.CopyBuffer(io.MultiWriter(output, hash), backupReader{ctx, input}, make([]byte, 64<<10))
	if copyErr == nil && (uint64(n) != uint64(source.file.Length) || string(hash.Sum(nil)) != string(source.file.SHA[:])) {
		copyErr = errors.New("backup source changed during copy")
	}
	var syncErr error
	if copyErr == nil {
		syncErr = output.Sync()
	}
	return errors.Join(copyErr, syncErr, output.Close(), store.SyncDirectory(filepath.Dir(target)))
}
func makeBackupDirectories(root, dir string) error {
	if dir == root {
		return privatePath(root, true)
	}
	if e := makeBackupDirectories(root, filepath.Dir(dir)); e != nil {
		return e
	}
	e := os.Mkdir(dir, 0700)
	if errors.Is(e, os.ErrExist) {
		return privatePath(dir, true)
	}
	if e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(dir))
}

// openBackupRepository は未完了構造を自動復旧する前に拒否し、コピー操作で正本を進めない。
func openBackupRepository(cfg Config) (*Repository, error) {
	if e := cfg.validate(); e != nil {
		return nil, e
	}
	if e := cfg.checkTLS(time.Now()); e != nil {
		return nil, e
	}
	if e := privatePath(cfg.DataDir, true); e != nil {
		return nil, e
	}
	if e := privatePath(filepath.Join(cfg.DataDir, ".lock"), false); e != nil {
		return nil, e
	}
	lock, e := platform.Lock(cfg.DataDir)
	if e != nil {
		return nil, e
	}
	if _, e = checkLockedPosting(cfg, false, true); e != nil {
		return nil, errors.Join(e, platform.Unlock(lock))
	}
	return openLockedPostingRepository(cfg, lock, func(string) {}, postcapture.Validate, "")
}
