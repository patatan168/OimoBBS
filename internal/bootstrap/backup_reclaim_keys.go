// 正本が使えない場合にも別保管鍵で期限切れ本文コピーを認証し、回収を再開する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"time"
)

// ReclaimBackupWithKeys は別保管鍵でコピーを認証し、期限切れかつapply時だけ回収する。
// 鍵bundleは除去しない。削除途中のpayload欠落を許容し、manifestを最後まで保持する。
func ReclaimBackupWithKeys(ctx context.Context, input, keys string, apply bool) (BackupReport, error) {
	return reclaimBackupWithKeys(ctx, input, keys, apply, time.Now, func(string) error { return nil })
}

func reclaimBackupWithKeys(ctx context.Context, input, keys string, apply bool, clock func() time.Time, boundary func(string) error) (report BackupReport, err error) {
	if err = separateBackupPaths(input, keys); err != nil {
		return report, err
	}
	if err = privatePath(filepath.Dir(input), true); err != nil {
		return report, err
	}
	if err = privatePath(input, true); err != nil {
		return report, err
	}
	bundle, err := loadBackupKeys(ctx, keys)
	if err != nil {
		return report, err
	}
	raw, err := readPrivate(filepath.Join(input, "manifest.json"), backupManifestLimit)
	if err != nil {
		return report, err
	}
	if sha256.Sum256(raw) != bundle.BackupSHA {
		return report, errors.New("backup manifest does not match key bundle")
	}
	key, err := backupKey(keys)
	if err != nil {
		return report, err
	}
	defer clear(key[:])
	m, report, err := decodeBackupManifest(raw, key, bundle.Site)
	if err != nil {
		return report, err
	}
	if !backupKeysBindingMatches(m, bundle) {
		return report, errors.New("backup binding mismatch")
	}
	if err = matchBackupInstance(m, bundle.Files[0].SHA); err != nil {
		return report, err
	}
	now := clock().UnixNano()
	if now < int64(bundle.Created) {
		return report, errors.New("backup reclamation clock regression")
	}
	report.Expired = now >= int64(m.Expires)
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
