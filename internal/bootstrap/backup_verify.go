// 認証manifest、全ファイル、所有者current、期限を照合し、公開復元の許可と区別する。
package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/store"
)

// VerifyOfflineBackup は現在のサイト鍵と照合し、期限内の完全なコピーだけを検証済みとする。
// 現在の削除台帳を適用した復元や、バックアップ内の全WAL再生を実行するAPIではない。
func VerifyOfflineBackup(ctx context.Context, cfg Config, input string) (BackupReport, error) {
	return verifyOfflineBackup(ctx, cfg, input, time.Now)
}
func verifyOfflineBackup(ctx context.Context, cfg Config, input string, clock func() time.Time) (report BackupReport, err error) {
	r, err := openBackupRepository(cfg)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	m, report, err := r.loadBackup(input)
	if err != nil {
		return report, err
	}
	if err = backupWindow(clock, m.Created, m.Expires); err != nil {
		return report, err
	}
	if err = verifyBackupFiles(ctx, input, m, true); err != nil {
		return report, err
	}
	if err = backupWindow(clock, m.Created, m.Expires); err != nil {
		return report, err
	}
	report.Verified = true
	return report, nil
}
func (r *Repository) loadBackup(input string) (backupManifest, BackupReport, error) {
	if e := r.candidatePath(input); e != nil {
		return backupManifest{}, BackupReport{}, e
	}
	if e := privatePath(input, true); e != nil {
		return backupManifest{}, BackupReport{}, e
	}
	key, e := backupKey(r.cfg.DataDir)
	if e != nil {
		return backupManifest{}, BackupReport{}, e
	}
	defer clear(key[:])
	raw, e := readPrivate(filepath.Join(input, "manifest.json"), backupManifestLimit)
	if e != nil {
		return backupManifest{}, BackupReport{}, e
	}
	r.mu.Lock()
	if e = r.available(); e != nil {
		r.mu.Unlock()
		return backupManifest{}, BackupReport{}, e
	}
	id := siteID(r.site.State())
	r.mu.Unlock()
	return decodeBackupManifest(raw, key, id)
}

// verifyBackupFiles はmanifestが列挙した集合と実directoryの完全一致を要求する。
func verifyBackupFiles(ctx context.Context, root string, m backupManifest, complete bool) error {
	if m.Schema != 7 {
		return errors.New("unsupported backup storage format")
	}
	files, dirs := backupInventory(m, complete)
	if e := walkBackupInventory(ctx, root, files, dirs, false); e != nil {
		return e
	}
	for _, entry := range m.Entries {
		for _, file := range entry.Files {
			actual, e := store.HashBackupFile(ctx, filepath.Join(root, filepath.FromSlash(backupEntryPath(entry)+"/"+file.Name)))
			if e != nil {
				return e
			}
			if actual.Length != file.Length || actual.SHA != file.SHA {
				return errors.New("backup file checksum mismatch")
			}
		}
		if entry.Kind != "metadata" {
			if e := verifyBackupCurrent(root, entry); e != nil {
				return e
			}
		}
	}
	if e := verifyBackupOptionalOmission(ctx, root, m); e != nil {
		return e
	}
	return verifyBackupRequiredOmission(ctx, root, m)
}
func backupInventory(m backupManifest, complete bool) (map[string]bool, map[string]bool) {
	files := map[string]bool{}
	dirs := map[string]bool{".": true}
	if complete {
		files["manifest.json"] = true
	}
	for _, entry := range m.Entries {
		for _, file := range entry.Files {
			name := backupEntryPath(entry) + "/" + file.Name
			files[name] = true
			for p := filepath.ToSlash(filepath.Dir(name)); p != "."; p = filepath.ToSlash(filepath.Dir(p)) {
				dirs[p] = true
			}
		}
	}
	return files, dirs
}
func walkBackupInventory(ctx context.Context, root string, files, dirs map[string]bool, missingAllowed bool) error {
	found := 0
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if !dirs[rel] {
				return errors.New("unlisted backup directory")
			}
			return privatePath(path, true)
		}
		if !files[rel] {
			return errors.New("unlisted backup file")
		}
		found++
		return privatePath(path, false)
	})
	if e == nil && !missingAllowed && found != len(files) {
		e = errors.New("missing backup file")
	}
	return e
}
func verifyBackupCurrent(root string, entry backupEntry) error {
	dir := filepath.Join(root, filepath.FromSlash(backupEntryPath(entry)))
	if entry.Kind == "thread" {
		m, _, e := store.InspectThreadFiles(dir)
		if e != nil {
			return e
		}
		if m.BoardID != entry.Owner || strconv.FormatUint(uint64(m.ThreadKey), 10) != entry.Subkey {
			return errors.New("backup thread owner mismatch")
		}
		return verifyBackupDelta(entry, m.Delta)
	}
	m, e := store.InspectControlManifest(dir)
	if e != nil {
		return e
	}
	kinds := map[string]uint16{"site": 1, "board": 2, "audit": 4, "evidence": 8, "job": 6, "deletion": 3}
	subkey := uint64(0)
	if entry.Subkey != "control" {
		subkey, e = strconv.ParseUint(entry.Subkey, 10, 64)
		if e != nil || strconv.FormatUint(subkey, 10) != entry.Subkey {
			return errors.New("invalid backup subkey")
		}
	}
	if m.Owner != entry.Owner || m.Kind != kinds[entry.Kind] || uint64(m.Subkey) != subkey {
		return errors.New("backup control owner mismatch")
	}
	return verifyBackupDelta(entry, m.Delta)
}
func verifyBackupDelta(entry backupEntry, delta store.Delta) error {
	if delta.RequiredSeq != entry.Sequence || delta.RequiredEnd != entry.RequiredEnd {
		return errors.New("backup required prefix mismatch")
	}
	for _, file := range entry.Files {
		if file.Name == delta.File && file.Length == delta.RequiredEnd && file.SHA == delta.RequiredSHA {
			return nil
		}
	}
	return errors.New("backup delta is not captured")
}

// backupDirectoryOrder は回収時に子directoryから親へ処理する。
func backupDirectoryDepth(path string) int { return strings.Count(path, "/") }
