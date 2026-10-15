// 停止中コピーに束縛した鍵を別領域へ保存し、秘密を結果へ含めず完成印を最後に置く。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

var backupKeyNames = []string{"instance.json", "keys/master-000001.key", "keys/evidence-000010.seed"}

// ExportBackupKeys は停止中の正本鍵を検証済みコピー専用の別directoryへ保存する。
// 出力は生鍵を含むため所有者限定とし、既存・途中出力は再利用しない。期限を延長しない。
func ExportBackupKeys(ctx context.Context, cfg Config, input, output string) (BackupReport, error) {
	return exportBackupKeys(ctx, cfg, input, output, time.Now, func(string) {})
}
func exportBackupKeys(ctx context.Context, cfg Config, input, output string, clock func() time.Time, boundary func(string)) (report BackupReport, err error) {
	r, err := openBackupRepository(cfg)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	return r.exportBackupKeys(ctx, input, output, clock, boundary)
}

// exportBackupKeys はコピー捕捉と同じ排他を保持したまま、鍵を別領域へ保存する。
func (r *Repository) exportBackupKeys(ctx context.Context, input, output string, clock func() time.Time, boundary func(string)) (report BackupReport, err error) {
	return r.exportBackupKeysWithSetup(ctx, input, output, clock, boundary, func(backupKeysManifest, []byte) error { return nil })
}

// exportBackupKeysWithSetup はroot/親同期後、鍵を書き出す前に任意の事前計画を保存する。
func (r *Repository) exportBackupKeysWithSetup(ctx context.Context, input, output string, clock func() time.Time, boundary func(string), setup func(backupKeysManifest, []byte) error) (report BackupReport, err error) {
	cfg := r.cfg
	if err = r.candidatePath(output); err != nil {
		return report, err
	}
	if err = separateBackupPaths(input, output); err != nil {
		return report, err
	}
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
	payloads := make(map[string][]byte)
	defer func() {
		for _, raw := range payloads {
			clear(raw)
		}
	}()
	bundle := backupKeysManifest{Schema: 1, Mode: "offline_keys", Backup: m.ID, Site: m.Site, Created: domain.Time(clock().UnixNano()), Expires: m.Expires, KeyIDs: m.KeyIDs}
	if m.Mode == "online_candidate" {
		bundle.Mode = "online_keys"
	}
	raw, err := readPrivate(filepath.Join(input, "manifest.json"), backupManifestLimit)
	if err != nil {
		return report, err
	}
	bundle.BackupSHA = sha256.Sum256(raw)
	for _, name := range backupKeyNames {
		limit := int64(4096)
		if name != "instance.json" {
			limit = 32
		}
		raw, err = readPrivate(filepath.Join(cfg.DataDir, filepath.FromSlash(name)), limit)
		if err != nil {
			return report, err
		}
		payloads[name] = raw
		bundle.Files = append(bundle.Files, backupFile{Name: name, Length: domain.U64(len(raw)), SHA: sha256.Sum256(raw)})
	}
	if err = matchBackupInstance(m, bundle.Files[0].SHA); err != nil {
		return report, err
	}
	key, err := backupKeysKey(cfg.DataDir)
	if err != nil {
		return report, err
	}
	defer clear(key[:])
	encoded, err := encodeBackupKeys(bundle, key)
	if err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = backupWindow(clock, bundle.Created, bundle.Expires); err != nil {
		return report, err
	}
	if err = backupCapacity(cfg.DataDir, filepath.Dir(output), uint64(len(encoded))+4096); err != nil {
		return report, err
	}
	if err = makePrivateDir(output); err != nil {
		return report, err
	}
	boundary("backup-keys:directory")
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = setup(bundle, encoded); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = makePrivateDir(filepath.Join(output, "keys")); err != nil {
		return report, err
	}
	for _, name := range backupKeyNames {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		if err = writeNew(filepath.Join(output, filepath.FromSlash(name)), payloads[name]); err != nil {
			return report, err
		}
		boundary("backup-keys:file")
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(filepath.Join(output, "keys")); err != nil {
		return report, err
	}
	if err = writeNew(filepath.Join(output, "bundle.pending"), encoded); err != nil {
		return report, err
	}
	boundary("backup-keys:manifest_synced")
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = backupWindow(clock, bundle.Created, bundle.Expires); err != nil {
		return report, err
	}
	if err = os.Rename(filepath.Join(output, "bundle.pending"), filepath.Join(output, "bundle.json")); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(output); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(filepath.Dir(output)); err != nil {
		return report, err
	}
	if _, err = verifyBackupWithKeys(ctx, input, output, clock); err != nil {
		return report, err
	}
	report.Verified = true
	return report, nil
}

// separateBackupPaths は同じ領域・親子領域への鍵の同梱を拒否する。
func separateBackupPaths(a, b string) error {
	for _, p := range []string{a, b} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("backup paths must be clean absolute directories")
		}
	}
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err != nil {
			return err
		}
		if rel == "." || filepath.IsLocal(rel) {
			return errors.New("backup and key bundle must be separate directories")
		}
	}
	return nil
}
func backupWindow(clock func() time.Time, created, expires domain.Time) error {
	now := clock().UnixNano()
	if now < int64(created) || now >= int64(expires) {
		return errors.New("backup is outside its retention window")
	}
	return nil
}
func matchBackupInstance(m backupManifest, sha domain.Hash) error {
	for _, e := range m.Entries {
		if e.Kind == "metadata" {
			for _, f := range e.Files {
				if f.Name == "instance.json" && f.SHA == sha {
					return nil
				}
			}
		}
	}
	return errors.New("backup instance does not match key bundle")
}

// VerifyBackupWithKeys は正本設定・データ領域に触れず、別保管鍵とコピーの完全一致を検証する。
// 公開復元、削除台帳の適用、全WAL再生の許可を返すAPIではない。
func VerifyBackupWithKeys(ctx context.Context, input, keys string) (BackupReport, error) {
	return verifyBackupWithKeys(ctx, input, keys, time.Now)
}
func verifyBackupWithKeys(ctx context.Context, input, keys string, clock func() time.Time) (report BackupReport, err error) {
	if err = separateBackupPaths(input, keys); err != nil {
		return report, err
	}
	bundle, err := loadBackupKeys(ctx, keys)
	if err != nil {
		return report, err
	}
	if err = backupWindow(clock, bundle.Created, bundle.Expires); err != nil {
		return report, err
	}
	if err = privatePath(input, true); err != nil {
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
	if err = verifyBackupFiles(ctx, input, m, true); err != nil {
		return report, err
	}
	if err = backupWindow(clock, bundle.Created, bundle.Expires); err != nil {
		return report, err
	}
	report.Verified = true
	return report, nil
}

// loadBackupKeys は固定集合・用途別MAC・鍵指紋・署名公開鍵を照合する。
func loadBackupKeys(ctx context.Context, root string) (backupKeysManifest, error) {
	files, dirs := backupKeysInventory()
	if err := walkBackupInventory(ctx, root, files, dirs, false); err != nil {
		return backupKeysManifest{}, err
	}
	key, err := backupKeysKey(root)
	if err != nil {
		return backupKeysManifest{}, err
	}
	defer clear(key[:])
	raw, err := readPrivate(filepath.Join(root, "bundle.json"), backupKeysLimit)
	if err != nil {
		return backupKeysManifest{}, err
	}
	m, err := decodeBackupKeys(raw, key)
	if err != nil {
		return m, err
	}
	for _, f := range m.Files {
		if err = ctx.Err(); err != nil {
			return m, err
		}
		contents, e := readPrivate(filepath.Join(root, filepath.FromSlash(f.Name)), int64(f.Length))
		if e != nil {
			return m, e
		}
		matches := uint64(len(contents)) == uint64(f.Length) && sha256.Sum256(contents) == f.SHA
		clear(contents)
		if !matches {
			return m, errors.New("key bundle file checksum mismatch")
		}
	}
	raw, err = readPrivate(filepath.Join(root, "instance.json"), 4096)
	if err != nil {
		return m, err
	}
	var marker instance
	if err = decodeBackupInstance(raw, &marker); err != nil {
		return m, err
	}
	if marker.SiteID != m.Site {
		return m, errors.New("key bundle site mismatch")
	}
	return m, checkKeys(root, marker)
}

// decodeBackupInstance は鍵に対応する初期化完了印の必須項目を照合する。
func decodeBackupInstance(raw []byte, marker *instance) error {
	if err := strictjson.Decode(raw, marker); err != nil {
		return err
	}
	if marker.Schema != storageFormatVersion || marker.SiteID == (domain.ID{}) || marker.MasterSHA == (domain.Hash{}) || marker.SigningPublic == (domain.Hash{}) {
		return errors.New("invalid key bundle instance")
	}
	return nil
}

func backupKeysInventory() (map[string]bool, map[string]bool) {
	files := map[string]bool{"bundle.json": true}
	for _, name := range backupKeyNames {
		files[name] = true
	}
	return files, map[string]bool{".": true, "keys": true}
}
