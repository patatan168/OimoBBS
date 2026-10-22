// 最新の完全な停止中保存先を検証し、別の保存先へ公開起動可能な状態で復元する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

// PublicRestoreReport は全ファイルの複写照合と製品再生が完了した場合だけ返す。
type PublicRestoreReport struct {
	Backup                *domain.ID `json:"backup_id,omitempty"`
	PayloadFilesRecovered int        `json:"payload_files_recovered,omitempty"`
	Site                  domain.ID  `json:"site_id"`
	Files                 int        `json:"files_verified"`
	Bytes                 int64      `json:"bytes_verified"`
	RestoreReady          bool       `json:"restore_ready"`
}

// RestorePublicRepository は最新正本の完全コピーを別directoryへ復元する。
// sourceは停止中の最新正本に限定する。旧backupとの合成や欠落した台帳の再作成はしない。
// 検証中は公開listenerを作らず、完成directoryのrenameまで通常起動先を作らない。
func RestorePublicRepository(ctx context.Context, source, target Config) (PublicRestoreReport, error) {
	return restorePublicRepository(ctx, source, target, "")
}

// RestorePublicRepositoryFromBackup は最新台帳側で欠けた本文ファイルだけを認証済み旧backupから補う。
// 最新のcurrent・制御・削除・解除・署名記録・鍵はsourceに必須とし、旧backupから置換しない。
func RestorePublicRepositoryFromBackup(ctx context.Context, source, target Config, backup string) (PublicRestoreReport, error) {
	if backup == "" {
		return PublicRestoreReport{}, errors.New("backup path required")
	}
	return restorePublicRepository(ctx, source, target, backup)
}

func restorePublicRepository(ctx context.Context, source, target Config, backup string) (report PublicRestoreReport, err error) {
	if err = source.validate(); err != nil {
		return report, err
	}
	if err = target.validate(); err != nil {
		return report, err
	}
	if err = target.checkTLS(time.Now()); err != nil {
		return report, err
	}
	if target.Edge != nil {
		if err = target.edgeTLS(&tls.Config{}); err != nil {
			return report, err
		}
	}
	if source.Public.BaseURL != target.Public.BaseURL {
		return report, errors.New("restore must preserve the public origin")
	}
	if err = separateBackupPaths(source.DataDir, target.DataDir); err != nil {
		return report, err
	}
	if backup != "" {
		for _, root := range []string{source.DataDir, target.DataDir} {
			if err = separateBackupPaths(root, backup); err != nil {
				return report, err
			}
		}
		if err = privatePath(backup, true); err != nil {
			return report, err
		}
	}
	if _, err = os.Lstat(target.DataDir); !errors.Is(err, os.ErrNotExist) {
		return report, errors.New("restore destination must not exist")
	}
	parent := filepath.Dir(target.DataDir)
	if err = privatePath(parent, true); err != nil {
		return report, err
	}
	parentLock, e := platform.Lock(parent)
	if e != nil {
		return report, e
	}
	defer func() {
		err = errors.Join(err, platform.Unlock(parentLock))
		if err != nil {
			report.RestoreReady = false
		}
	}()
	if err = privatePath(source.DataDir, true); err != nil {
		return report, err
	}
	lock, err := platform.Lock(source.DataDir)
	if err != nil {
		return report, err
	}
	defer func() {
		err = errors.Join(err, platform.Unlock(lock))
		if err != nil {
			report.RestoreReady = false
		}
	}()
	var candidate backupManifest
	if backup == "" {
		checked, e := checkLockedPosting(source, true, true)
		if e != nil {
			return report, e
		}
		report.Site = checked.SiteID
	} else {
		backupParent := filepath.Dir(backup)
		if backupParent != parent {
			unlock, e := lockBackupDirectories(backupParent)
			if e != nil {
				return report, e
			}
			defer func() {
				err = errors.Join(err, unlock())
				if err != nil {
					report.RestoreReady = false
				}
			}()
		}
		candidate, err = loadRestoreBackup(ctx, source, backup)
		if err != nil {
			return report, err
		}
		report.Site = candidate.Site
		report.Backup = &candidate.ID
	}
	work, err := os.MkdirTemp(parent, ".public-restore-")
	if err != nil {
		return report, err
	}
	defer func() {
		if work != "" {
			err = errors.Join(err, os.RemoveAll(work), store.SyncDirectory(parent))
		}
	}()
	if err = writeNew(filepath.Join(work, backupReplayGate), []byte("{}")); err != nil {
		return report, err
	}
	err = filepath.WalkDir(source.DataDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		relative, e := filepath.Rel(source.DataDir, path)
		if e != nil {
			return e
		}
		if relative == "." {
			return nil
		}
		if e = privatePath(path, entry.IsDir()); e != nil {
			return e
		}
		output := filepath.Join(work, relative)
		if entry.IsDir() {
			return makePrivateDir(output)
		}
		count, e := copyRestoreFile(ctx, path, output)
		if e == nil {
			report.Files++
			report.Bytes += count
		}
		return e
	})
	if err != nil {
		return report, err
	}
	if backup != "" {
		if err = fillRestorePayloads(ctx, backup, work, candidate, &report); err != nil {
			return report, err
		}
	}
	validation := target
	validation.DataDir = work
	workLock, err := platform.Lock(work)
	if err != nil {
		return report, err
	}
	restored, err := openLockedPostingRepository(validation, workLock, func(string) {}, postcapture.Validate, backupReplayGate)
	if err != nil {
		return report, err
	}
	if err = restored.Close(); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if backup != "" {
		if err = backupWindow(time.Now, candidate.Created, candidate.Expires); err != nil {
			return report, err
		}
	}
	if err = os.Remove(filepath.Join(work, backupReplayGate)); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(work); err != nil {
		return report, err
	}
	if _, e := os.Lstat(target.DataDir); !errors.Is(e, os.ErrNotExist) {
		return report, errors.New("restore destination appeared during verification")
	}
	if err = os.Rename(work, target.DataDir); err != nil {
		return report, err
	}
	work = ""
	if err = store.SyncDirectory(parent); err != nil {
		return report, err
	}
	report.RestoreReady = true
	return report, nil
}

// copyRestoreFile は内容hashを読み直して照合し、鍵や原本をhardlinkで共有しない。
func copyRestoreFile(ctx context.Context, source, target string) (count int64, err error) {
	in, err := os.Open(source)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, in.Close()) }()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 0, err
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		n, e := in.Read(buffer)
		if n > 0 {
			var written int
			written, err = out.Write(buffer[:n])
			if err == nil && written != n {
				err = io.ErrShortWrite
			}
			if err != nil {
				break
			}
			hash.Write(buffer[:n])
			count += int64(n)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			err = e
			break
		}
	}
	clear(buffer)
	if err == nil {
		err = out.Sync()
	}
	err = errors.Join(err, out.Close())
	if err != nil {
		return count, err
	}
	verify, err := os.Open(target)
	if err != nil {
		return count, err
	}
	second := sha256.New()
	_, readErr := io.Copy(second, verify)
	err = errors.Join(readErr, verify.Close())
	if err == nil && string(hash.Sum(nil)) != string(second.Sum(nil)) {
		err = errors.New("restore copy hash mismatch")
	}
	if err == nil {
		err = store.SyncDirectory(filepath.Dir(target))
	}
	return count, err
}
