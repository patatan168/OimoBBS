// 鍵bundleの固定ファイル集合・コピーとの対応・期限を専用MACで認証する。
package bootstrap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
)

const backupKeysLimit = 16384

type backupKeysManifest struct {
	Schema    uint32       `json:"schema"`
	Mode      string       `json:"mode"`
	Backup    domain.ID    `json:"backup_id"`
	BackupSHA domain.Hash  `json:"backup_manifest_sha256"`
	Site      domain.ID    `json:"site_id"`
	Created   domain.Time  `json:"created_at_ns"`
	Expires   domain.Time  `json:"expires_at_ns"`
	KeyIDs    []uint32     `json:"key_ids"`
	Files     []backupFile `json:"files"`
}

func backupKeysKey(root string) (domain.Hash, error) {
	master, err := readPrivate(filepath.Join(root, "keys/master-000001.key"), 32)
	if err != nil {
		return domain.Hash{}, err
	}
	defer clear(master)
	return identity.DeriveKey(master, "backup_key_bundle", 1)
}
func validateBackupKeys(m backupKeysManifest) error {
	if m.Schema != 1 || (m.Mode != "offline_keys" && m.Mode != "online_keys") || m.Backup == (domain.ID{}) || m.Site == (domain.ID{}) || m.BackupSHA == (domain.Hash{}) || m.Created <= 0 || m.Expires <= m.Created || m.Expires-m.Created > domain.Time(backupRetention) || len(m.KeyIDs) != 2 || m.KeyIDs[0] != 1 || m.KeyIDs[1] != 10 || len(m.Files) != len(backupKeyNames) {
		return errors.New("invalid key bundle manifest")
	}
	for i, f := range m.Files {
		if f.Name != backupKeyNames[i] || f.SHA == (domain.Hash{}) || i == 0 && (f.Length == 0 || f.Length > 4096) || i > 0 && f.Length != 32 {
			return errors.New("invalid key bundle file")
		}
	}
	return nil
}
func encodeBackupKeys(m backupKeysManifest, key domain.Hash) ([]byte, error) {
	if err := validateBackupKeys(m); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return json.Marshal(backupEnvelope{raw, sha256.Sum256(raw), identity.MAC(key[:], "oimo/backup-key-bundle/v1", raw)})
}
func decodeBackupKeys(raw []byte, key domain.Hash) (backupKeysManifest, error) {
	var env backupEnvelope
	var m backupKeysManifest
	if len(raw) > backupKeysLimit {
		return m, errors.New("key bundle manifest budget exceeded")
	}
	if err := strictjson.Decode(raw, &env); err != nil {
		return m, err
	}
	mac := identity.MAC(key[:], "oimo/backup-key-bundle/v1", env.Manifest)
	if sha256.Sum256(env.Manifest) != env.SHA || !hmac.Equal(mac[:], env.MAC[:]) {
		return m, errors.New("key bundle authentication failed")
	}
	if err := strictjson.Decode(env.Manifest, &m); err != nil {
		return m, err
	}
	return m, validateBackupKeys(m)
}

// backupKeysBindingMatches は認証済み本文と鍵束のID・期限・取得順・オンライン用途を照合する。
func backupKeysBindingMatches(body backupManifest, keys backupKeysManifest) bool {
	mode := "offline_keys"
	if body.Mode == "online_candidate" {
		mode = "online_keys"
	}
	return keys.Mode == mode && body.Site == keys.Site && body.ID == keys.Backup && body.Expires == keys.Expires && keys.Created >= body.Created
}
