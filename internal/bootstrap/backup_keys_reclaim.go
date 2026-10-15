// 正本の鍵で期限切れbundleを認証し、bundle鍵の削除途中でも再開できる回収を提供する。
package bootstrap

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
)

// ReclaimBackupKeys は停止中正本の鍵でbundleを認証し、失効済みかつapply時だけ回収する。
// bundle自身の鍵が既に削除されていても再開できる。未完成・未列挙・別siteは拒否する。
func ReclaimBackupKeys(ctx context.Context, cfg Config, input string, apply bool) (BackupReport, error) {
	return reclaimBackupKeys(ctx, cfg, input, apply, time.Now, func(string) error { return nil })
}
func reclaimBackupKeys(ctx context.Context, cfg Config, input string, apply bool, clock func() time.Time, boundary func(string) error) (report BackupReport, err error) {
	r, err := openBackupRepository(cfg)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	if err = r.candidatePath(input); err != nil {
		return report, err
	}
	if err = privatePath(input, true); err != nil {
		return report, err
	}
	key, err := backupKeysKey(cfg.DataDir)
	if err != nil {
		return report, err
	}
	defer clear(key[:])
	raw, err := readPrivate(filepath.Join(input, "bundle.json"), backupKeysLimit)
	if err != nil {
		return report, err
	}
	m, err := decodeBackupKeys(raw, key)
	if err != nil {
		return report, err
	}
	if m.Site != siteID(r.site.State()) {
		return report, errors.New("key bundle belongs to another site")
	}
	now := clock().UnixNano()
	if now < int64(m.Created) {
		return report, errors.New("key bundle reclamation clock regression")
	}
	report = BackupReport{ID: m.Backup, Expires: m.Expires, Files: len(m.Files), Expired: now >= int64(m.Expires)}
	for _, f := range m.Files {
		report.Bytes += domain.U64(f.Length)
	}
	files, dirs := backupKeysInventory()
	if err = walkBackupInventory(ctx, input, files, dirs, report.Expired); err != nil {
		return report, err
	}
	if !report.Expired || !apply {
		return report, nil
	}
	if err = reclaimBackupInventory(ctx, input, files, dirs, "bundle.json", boundary); err != nil {
		return report, err
	}
	report.Applied = true
	return report, nil
}
