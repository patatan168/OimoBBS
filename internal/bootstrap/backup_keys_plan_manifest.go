// 鍵回収計画を別保管の公開完了印へ署名で束縛し、秘密鍵削除後も認証できる形にする。
package bootstrap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"

	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

const backupKeysPlanLimit = 64 << 10
const backupKeysRetireSuffix = ".retired.pending"

type backupKeysCleanupPlan struct {
	Schema    uint32             `json:"schema"`
	Mode      string             `json:"mode"`
	Root      string             `json:"root"`
	Plan      string             `json:"plan_file"`
	Device    domain.U64         `json:"device"`
	Inode     domain.U64         `json:"inode"`
	Created   domain.Time        `json:"created_at_ns"`
	TrustSHA  domain.Hash        `json:"trust_instance_sha256"`
	BundleSHA domain.Hash        `json:"bundle_sha256"`
	Bundle    backupKeysManifest `json:"bundle"`
}

type backupKeysPlanEnvelope struct {
	Plan         json.RawMessage `json:"plan"`
	SHA          domain.Hash     `json:"plan_sha256"`
	SigningKeyID uint32          `json:"signing_key_id"`
	Signature    string          `json:"signature"`
	Retired      bool            `json:"retired"`
}

func validateBackupKeysPlan(p backupKeysCleanupPlan) error {
	if p.Schema != 1 || p.Mode != "expired_keys_only" || !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) != p.Root || len(p.Root) > 4096 || !filepath.IsAbs(p.Plan) || filepath.Clean(p.Plan) != p.Plan || len(p.Plan)+len(backupKeysRetireSuffix) > 4096 || len(filepath.Base(p.Plan))+len(backupKeysRetireSuffix) > 255 || p.Inode == 0 || p.Created < p.Bundle.Created || p.TrustSHA == (domain.Hash{}) || p.BundleSHA == (domain.Hash{}) {
		return errors.New("invalid key cleanup plan")
	}
	return validateBackupKeys(p.Bundle)
}

// backupKeysPlanMessage は投稿証跡の署名と混同しない固定用途名と元JSONのhashを署名対象にする。
func backupKeysPlanMessage(hash domain.Hash) []byte {
	return append([]byte("oimo/backup-keys-cleanup/v1\x00"), hash[:]...)
}

func encodeBackupKeysPlan(p backupKeysCleanupPlan, key ed25519.PrivateKey) ([]byte, error) {
	if e := validateBackupKeysPlan(p); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	hash := sha256.Sum256(raw)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(key, backupKeysPlanMessage(hash)))
	return json.Marshal(backupKeysPlanEnvelope{raw, hash, 10, signature, false})
}

func decodeBackupKeysPlan(raw []byte, trust instance, trustRaw []byte) (backupKeysCleanupPlan, error) {
	return decodeBackupKeysPlanState(raw, trust, trustRaw, false)
}

// decodeBackupKeysPlanState は登録済み計画の退役再開に限り、使用済みでも署名/所有境界を検証する。
func decodeBackupKeysPlanState(raw []byte, trust instance, trustRaw []byte, allowRetired bool) (backupKeysCleanupPlan, error) {
	var p backupKeysCleanupPlan
	var env backupKeysPlanEnvelope
	if len(raw) > backupKeysPlanLimit {
		return p, errors.New("key cleanup plan budget exceeded")
	}
	if e := strictjson.Decode(raw, &env); e != nil {
		return p, e
	}
	if env.Retired && !allowRetired {
		return p, errors.New("key cleanup plan is retired; inspect any remaining empty root")
	}
	signature, e := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if e != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != env.Signature || env.SigningKeyID != 10 || sha256.Sum256(env.Plan) != env.SHA || !ed25519.Verify(ed25519.PublicKey(trust.SigningPublic[:]), backupKeysPlanMessage(env.SHA), signature) {
		return p, errors.New("key cleanup plan signature mismatch")
	}
	if e = strictjson.Decode(env.Plan, &p); e != nil {
		return p, e
	}
	if e = validateBackupKeysPlan(p); e != nil {
		return p, e
	}
	if p.TrustSHA != sha256.Sum256(trustRaw) || p.Bundle.Site != trust.SiteID {
		return p, errors.New("key cleanup plan trust mismatch")
	}
	return p, nil
}

// loadBackupTrust は所有者が別保管した公開完了印を読む。計画内の公開鍵は信頼根にしない。
func loadBackupTrust(path string) (instance, []byte, error) {
	var marker instance
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return marker, nil, errors.New("trust instance must be a clean absolute file")
	}
	raw, e := readPrivate(path, 4096)
	if e != nil {
		return marker, nil, e
	}
	if e = strictjson.Decode(raw, &marker); e != nil {
		return marker, nil, e
	}
	if marker.Schema != storageFormatVersion || marker.SiteID == (domain.ID{}) || marker.MasterSHA == (domain.Hash{}) || marker.SigningPublic == (domain.Hash{}) {
		return marker, nil, errors.New("invalid trust instance")
	}
	return marker, raw, nil
}
