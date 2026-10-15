// 鍵書込み前に所有境界と期限を署名し、正本喪失後も未完成鍵束を回収できる計画を保存する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// backupPartialKeysPlan は完成印を許さない鍵束専用の事前計画。生鍵を含めない。
type backupPartialKeysPlan struct {
	Schema      uint32             `json:"schema"`
	Mode        string             `json:"mode"`
	Root        string             `json:"root"`
	Plan        string             `json:"plan_file"`
	Device      domain.U64         `json:"device"`
	Inode       domain.U64         `json:"inode"`
	TrustSHA    domain.Hash        `json:"trust_instance_sha256"`
	BundleSHA   domain.Hash        `json:"bundle_sha256"`
	BundleBytes domain.U64         `json:"bundle_bytes"`
	Bundle      backupKeysManifest `json:"bundle"`
}

// PlannedBackupKeysExportReport は事前計画保存・鍵束完成・正本Closeの成否を分ける。
type PlannedBackupKeysExportReport struct {
	Phase        string        `json:"phase"`
	Keys         *BackupReport `json:"keys,omitempty"`
	Planned      bool          `json:"planned"`
	Complete     bool          `json:"complete"`
	RestoreReady bool          `json:"restore_ready"`
}

// ExportPlannedBackupKeys は停止中正本から、本文コピーに対応する鍵束と事前署名計画を新規作成する。
// trust/planを本文・鍵束・正本の外へ置く。失敗時も出力を保持し、秘密を結果へ含めない。
func ExportPlannedBackupKeys(ctx context.Context, cfg Config, input, output, trust, plan string) (PlannedBackupKeysExportReport, error) {
	return exportPlannedBackupKeys(ctx, cfg, input, output, trust, plan, time.Now, func(string) {})
}

func exportPlannedBackupKeys(ctx context.Context, cfg Config, input, output, trust, plan string, clock func() time.Time, boundary func(string)) (report PlannedBackupKeysExportReport, err error) {
	report.Phase = "source_open"
	if err = ctx.Err(); err != nil {
		return report, err
	}
	r, err := openBackupRepository(cfg)
	if err != nil {
		return report, err
	}
	defer func() {
		err = errors.Join(err, r.Close())
		if err != nil {
			report.Complete = false
		}
	}()
	report.Phase = "preflight"
	for _, external := range []string{output, trust, plan} {
		if err = separateBackupPaths(input, external); err != nil {
			return report, err
		}
	}
	signer, err := r.preparePartialBackupSigner(output, trust, plan)
	if err != nil {
		return report, err
	}
	defer clear(signer.key)
	report.Phase = "keys"
	keys, err := r.exportBackupKeysWithSetup(ctx, input, output, clock, boundary, func(m backupKeysManifest, raw []byte) error {
		if e := signer.saveKeys(ctx, m, raw); e != nil {
			return e
		}
		report.Planned = true
		boundary("backup-keys:partial_plan_synced")
		return ctx.Err()
	})
	if keys.ID != (domain.ID{}) {
		report.Keys = &keys
	}
	if err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	report.Phase, report.Complete = "complete", true
	return report, nil
}

// saveKeys はroot同期後、最初の鍵fileより前に署名計画を同期保存する。
func (s *partialBackupSigner) saveKeys(ctx context.Context, m backupKeysManifest, raw []byte) error {
	dev, inode, e := replayRootIdentity(s.root)
	if e != nil {
		return e
	}
	p := backupPartialKeysPlan{3, "expired_partial_keys_only", s.root, s.plan, dev, inode, s.trustSHA, sha256.Sum256(raw), domain.U64(len(raw)), m}
	if m.Mode == "online_keys" {
		p.Schema = 3
		p.Mode = "expired_online_keys_inventory"
	}
	encoded, e := encodePartialKeysPlan(p, s.key)
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = writeNew(s.plan, encoded); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(s.plan))
}

// validatePartialKeysPlan は固定配置・署名済み長さ上限・鍵束の元期限を検査する。
func validatePartialKeysPlan(p backupPartialKeysPlan) error {
	if (p.Schema != 3 || p.Mode != "expired_partial_keys_only" && !(p.Mode == "expired_online_keys_inventory" && p.Bundle.Mode == "online_keys")) || !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) != p.Root || len(p.Root) > 4096 || !filepath.IsAbs(p.Plan) || filepath.Clean(p.Plan) != p.Plan || len(p.Plan)+len(backupKeysRetireSuffix) > 4096 || len(filepath.Base(p.Plan))+len(backupKeysRetireSuffix) > 255 || p.Inode == 0 || p.TrustSHA == (domain.Hash{}) || p.BundleSHA == (domain.Hash{}) || p.BundleBytes == 0 || p.BundleBytes > backupKeysLimit {
		return errors.New("invalid partial key cleanup plan")
	}
	return validateBackupKeys(p.Bundle)
}

// partialKeysPlanMessage は本文/完成鍵束/証跡署名と混同しない固定用途名。
func partialKeysPlanMessage(hash domain.Hash) []byte {
	return append([]byte("oimo/backup-partial-keys-cleanup/v1\x00"), hash[:]...)
}

func encodePartialKeysPlan(p backupPartialKeysPlan, key ed25519.PrivateKey) ([]byte, error) {
	if e := validatePartialKeysPlan(p); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	hash := sha256.Sum256(raw)
	encoded, e := json.Marshal(backupKeysPlanEnvelope{raw, hash, 10, base64.StdEncoding.EncodeToString(ed25519.Sign(key, partialKeysPlanSigningMessage(p, hash))), false})
	if e == nil && len(encoded) > backupKeysPlanLimit {
		e = errors.New("partial key plan budget exceeded")
	}
	return encoded, e
}

func decodePartialKeysPlan(raw []byte, trust instance, trustRaw []byte) (backupPartialKeysPlan, error) {
	return decodePartialKeysPlanState(raw, trust, trustRaw, false)
}

// decodePartialKeysPlanState は登録済み計画の退役再開に限り、使用済みでも署名/所有境界を検証する。
func decodePartialKeysPlanState(raw []byte, trust instance, trustRaw []byte, allowRetired bool) (backupPartialKeysPlan, error) {
	var p backupPartialKeysPlan
	var env backupKeysPlanEnvelope
	if len(raw) > backupKeysPlanLimit {
		return p, errors.New("partial key plan budget exceeded")
	}
	if e := strictjson.Decode(raw, &env); e != nil {
		return p, e
	}
	if env.Retired && !allowRetired {
		return p, errors.New("partial key plan is retired; inspect remaining root")
	}
	if e := strictjson.Decode(env.Plan, &p); e != nil {
		return p, e
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != env.Signature || env.SigningKeyID != 10 || sha256.Sum256(env.Plan) != env.SHA || !ed25519.Verify(ed25519.PublicKey(trust.SigningPublic[:]), partialKeysPlanSigningMessage(p, env.SHA), sig) {
		return p, errors.New("partial key plan signature mismatch")
	}
	if e = validatePartialKeysPlan(p); e != nil {
		return p, e
	}
	if p.TrustSHA != sha256.Sum256(trustRaw) || p.Bundle.Site != trust.SiteID {
		return p, errors.New("partial key plan trust mismatch")
	}
	return p, nil
}

// partialKeysPlanSigningMessage は完成印も事前許可するオンライン計画を別用途に分ける。
func partialKeysPlanSigningMessage(p backupPartialKeysPlan, hash domain.Hash) []byte {
	if p.Mode == "expired_online_keys_inventory" {
		return append([]byte("oimo/online-backup-keys-inventory/v2\x00"), hash[:]...)
	}
	return partialKeysPlanMessage(hash)
}
