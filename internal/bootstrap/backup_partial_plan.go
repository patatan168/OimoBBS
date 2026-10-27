// コピー開始前の外部署名計画で、完成印を持たない出力の所有境界と期限を確定する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const backupPartialPlanLimit = backupManifestLimit + (64 << 10)

type backupPartialCleanupPlan struct {
	Schema        uint32         `json:"schema"`
	Mode          string         `json:"mode"`
	Root          string         `json:"root"`
	Plan          string         `json:"plan_file"`
	Device        domain.U64     `json:"device"`
	Inode         domain.U64     `json:"inode"`
	TrustSHA      domain.Hash    `json:"trust_instance_sha256"`
	ManifestSHA   domain.Hash    `json:"manifest_sha256"`
	ManifestBytes domain.U64     `json:"manifest_bytes"`
	Manifest      backupManifest `json:"manifest"`
}

// PlannedBackupCaptureReport は計画保存とコピー完成を分けた結果。失敗時も途中出力を保持する。
type PlannedBackupCaptureReport struct {
	Phase        string        `json:"phase"`
	Capture      *BackupReport `json:"capture,omitempty"`
	Planned      bool          `json:"planned"`
	Complete     bool          `json:"complete"`
	RestoreReady bool          `json:"restore_ready"`
}

// CapturePlannedOfflineBackup は新規コピーのpayload前に外部署名計画を同期保存する。
// trustは正本公開完了印の別保管file、planは新規0600file。両者をコピー外へ置く。
func CapturePlannedOfflineBackup(ctx context.Context, cfg Config, output, trust, plan string) (PlannedBackupCaptureReport, error) {
	return capturePlannedOfflineBackup(ctx, cfg, output, trust, plan, time.Now, func(string) {})
}

func capturePlannedOfflineBackup(ctx context.Context, cfg Config, output, trust, plan string, clock func() time.Time, boundary func(string)) (report PlannedBackupCaptureReport, err error) {
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
	signer, err := r.preparePartialBackupSigner(output, trust, plan)
	if err != nil {
		return report, err
	}
	defer clear(signer.key)
	report.Phase = "capture"
	captured, err := r.captureOfflineBackupWithSetup(ctx, output, clock, boundary, func(m backupManifest, raw []byte) error {
		if e := signer.save(ctx, m, raw); e != nil {
			return e
		}
		report.Planned = true
		boundary("backup:partial_plan_synced")
		return ctx.Err()
	})
	if captured.ID != (domain.ID{}) {
		report.Capture = &captured
	}
	if err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	report.Phase = "complete"
	report.Complete = true
	return report, nil
}

// partialBackupSigner は停止中正本で検査した署名鍵と、固定位置・公開信頼根指紋。
// 利用側は終了時にkeyをclearする。seedは生成関数内だけで保持する。
type partialBackupSigner struct {
	root, plan string
	trustSHA   domain.Hash
	key        ed25519.PrivateKey
}

// preparePartialBackupSigner は出力前に配置/新規性と正本一致を検査し、秘密鍵を準備する。
func (r *Repository) preparePartialBackupSigner(output, trust, plan string) (*partialBackupSigner, error) {
	cfg := r.cfg
	var err error
	for _, p := range []string{output, trust, plan} {
		if err = r.candidatePath(p); err != nil {
			return nil, err
		}
	}
	if err = backupKeysPlanPaths(output, trust, plan); err != nil {
		return nil, err
	}
	for _, p := range []string{output, plan} {
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			return nil, errors.New("planned capture requires new output and plan")
		}
	}
	marker, trustRaw, err := loadBackupTrust(trust)
	if err != nil {
		return nil, err
	}
	source, sourceRaw, err := loadBackupTrust(filepath.Join(cfg.DataDir, "instance.json"))
	if err != nil {
		return nil, err
	}
	if marker != source || sha256.Sum256(trustRaw) != sha256.Sum256(sourceRaw) {
		return nil, errors.New("partial plan trust does not match source")
	}
	seed, err := readPrivate(filepath.Join(cfg.DataDir, "keys/evidence-000010.seed"), ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid partial plan signing seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	if !ed25519.PublicKey(marker.SigningPublic[:]).Equal(key.Public()) {
		clear(key)
		return nil, errors.New("partial plan signing key does not match trust")
	}
	return &partialBackupSigner{output, plan, sha256.Sum256(trustRaw), key}, nil
}

// save はroot同期後、payload前に署名計画を新規fileへ保存して親を同期する。
func (s *partialBackupSigner) save(ctx context.Context, m backupManifest, raw []byte) error {
	dev, inode, e := replayRootIdentity(s.root)
	if e != nil {
		return e
	}
	p := backupPartialCleanupPlan{1, "expired_partial_copy_only", s.root, s.plan, dev, inode, s.trustSHA, sha256.Sum256(raw), domain.U64(len(raw)), m}
	encoded, e := encodeBackupPartialPlan(p, s.key)
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

// validateBackupPartialPlan は完成印なしの回収専用計画と元manifestの上限を検査する。
func validateBackupPartialPlan(p backupPartialCleanupPlan) error {
	if p.Schema != 1 || p.Mode != "expired_partial_copy_only" || !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) != p.Root || len(p.Root) > 4096 || !filepath.IsAbs(p.Plan) || filepath.Clean(p.Plan) != p.Plan || len(p.Plan)+len(backupKeysRetireSuffix) > 4096 || len(filepath.Base(p.Plan))+len(backupKeysRetireSuffix) > 255 || p.Inode == 0 || p.TrustSHA == (domain.Hash{}) || p.ManifestSHA == (domain.Hash{}) || p.ManifestBytes == 0 || p.ManifestBytes > backupManifestLimit {
		return errors.New("invalid partial backup cleanup plan")
	}
	_, e := validateBackupManifest(p.Manifest)
	return e
}

// backupPartialPlanMessage は鍵束/証跡署名と区別する専用の用途名とhash。
func backupPartialPlanMessage(hash domain.Hash) []byte {
	return append([]byte("oimo/backup-partial-cleanup/v1\x00"), hash[:]...)
}

func encodeBackupPartialPlan(p backupPartialCleanupPlan, key ed25519.PrivateKey) ([]byte, error) {
	if e := validateBackupPartialPlan(p); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	hash := sha256.Sum256(raw)
	env := backupKeysPlanEnvelope{raw, hash, 10, base64.StdEncoding.EncodeToString(ed25519.Sign(key, backupPartialPlanMessage(hash))), false}
	encoded, e := json.Marshal(env)
	if e == nil && len(encoded) > backupPartialPlanLimit {
		e = errors.New("partial cleanup plan budget exceeded")
	}
	return encoded, e
}

func decodeBackupPartialPlan(raw []byte, trust instance, trustRaw []byte) (backupPartialCleanupPlan, error) {
	return decodeBackupPartialPlanState(raw, trust, trustRaw, false)
}

// decodeBackupPartialPlanState は登録済み計画の退役再開に限り、使用済みでも署名/所有境界を検証する。
func decodeBackupPartialPlanState(raw []byte, trust instance, trustRaw []byte, allowRetired bool) (backupPartialCleanupPlan, error) {
	var p backupPartialCleanupPlan
	var env backupKeysPlanEnvelope
	if len(raw) > backupPartialPlanLimit {
		return p, errors.New("partial cleanup plan budget exceeded")
	}
	if e := strictjson.Decode(raw, &env); e != nil {
		return p, e
	}
	if env.Retired && !allowRetired {
		return p, errors.New("partial cleanup plan is retired; inspect remaining root")
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != env.Signature || env.SigningKeyID != 10 || sha256.Sum256(env.Plan) != env.SHA || !ed25519.Verify(ed25519.PublicKey(trust.SigningPublic[:]), backupPartialPlanMessage(env.SHA), sig) {
		return p, errors.New("partial cleanup plan signature mismatch")
	}
	if e = strictjson.Decode(env.Plan, &p); e != nil {
		return p, e
	}
	if e = validateBackupPartialPlan(p); e != nil {
		return p, e
	}
	if p.TrustSHA != sha256.Sum256(trustRaw) || p.Manifest.Site != trust.SiteID {
		return p, errors.New("partial cleanup plan trust mismatch")
	}
	return p, nil
}
