// 停止中正本から公開信頼根と外部署名計画を作成する。生鍵は出力しない。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// BackupTrustReport は別保管した公開完了印の結果。秘密鍵や復元許可は含めない。
type BackupTrustReport struct {
	Site         *domain.ID `json:"site_id,omitempty"`
	SigningKeyID uint32     `json:"signing_key_id"`
	Exported     bool       `json:"exported"`
	RestoreReady bool       `json:"restore_ready"`
}

// BackupKeysPlanReport は鍵回収用の外部署名計画の結果。鍵束の削除は行わない。
type BackupKeysPlanReport struct {
	Backup       *BackupReport `json:"backup,omitempty"`
	Planned      bool          `json:"planned"`
	RestoreReady bool          `json:"restore_ready"`
}

// ExportBackupTrust は停止中正本のinstance.jsonを領域外の新規0600fileへ同期して別保管する。
// これは公開鍵と指紋だけで、生鍵を含まない。所有者は回収する鍵束と別領域で保持する。
func ExportBackupTrust(ctx context.Context, cfg Config, output string) (report BackupTrustReport, err error) {
	if err = ctx.Err(); err != nil {
		return report, err
	}
	r, err := openBackupRepository(cfg)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	if err = r.candidatePath(output); err != nil {
		return report, err
	}
	marker, raw, err := loadBackupTrust(filepath.Join(cfg.DataDir, "instance.json"))
	if err != nil {
		return report, err
	}
	report.Site = &marker.SiteID
	report.SigningKeyID = 10
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = writeNew(output, raw); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(filepath.Dir(output)); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	report.Exported = true
	return report, nil
}

// PlanBackupKeysReclamation は正本の認証鍵でbundleを検査し、公開信頼根に対応する署名計画を保存する。
// input/plan/trustは互いに別file/領域で、出力は新規0600file。期限を延長せず、bundleは変更しない。
func PlanBackupKeysReclamation(ctx context.Context, cfg Config, input, trust, output string) (BackupKeysPlanReport, error) {
	return planBackupKeysReclamation(ctx, cfg, input, trust, output, time.Now)
}

func planBackupKeysReclamation(ctx context.Context, cfg Config, input, trust, output string, clock func() time.Time) (report BackupKeysPlanReport, err error) {
	if err = ctx.Err(); err != nil {
		return report, err
	}
	r, err := openBackupRepository(cfg)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	return r.planBackupKeysReclamation(ctx, input, trust, output, clock)
}

// planBackupKeysReclamation は一括作成と同じ正本排他下で完成鍵束を署名する。
func (r *Repository) planBackupKeysReclamation(ctx context.Context, input, trust, output string, clock func() time.Time) (report BackupKeysPlanReport, err error) {
	cfg := r.cfg
	if err = ctx.Err(); err != nil {
		return report, err
	}
	for _, path := range []string{input, trust, output} {
		if err = r.candidatePath(path); err != nil {
			return report, err
		}
	}
	if err = backupKeysPlanPaths(input, trust, output); err != nil {
		return report, err
	}
	marker, trustRaw, err := loadBackupTrust(trust)
	if err != nil {
		return report, err
	}
	sourceMarker, sourceRaw, err := loadBackupTrust(filepath.Join(cfg.DataDir, "instance.json"))
	if err != nil {
		return report, err
	}
	if marker != sourceMarker || sha256.Sum256(trustRaw) != sha256.Sum256(sourceRaw) {
		return report, errors.New("trust instance does not match source")
	}
	dev, inode, err := replayRootIdentity(input)
	if err != nil {
		return report, err
	}
	raw, err := readPrivate(filepath.Join(input, "bundle.json"), backupKeysLimit)
	if err != nil {
		return report, err
	}
	key, err := backupKeysKey(cfg.DataDir)
	if err != nil {
		return report, err
	}
	defer clear(key[:])
	bundle, err := decodeBackupKeys(raw, key)
	if err != nil {
		return report, err
	}
	if bundle.Site != marker.SiteID {
		return report, errors.New("key bundle belongs to another site")
	}
	backupReport := backupKeysReclaimReport(bundle, clock())
	report.Backup = &backupReport
	if clock().UnixNano() < int64(bundle.Created) {
		return report, errors.New("key plan clock regression")
	}
	files, dirs := backupKeysInventory()
	if err = walkBackupInventory(ctx, input, files, dirs, report.Backup.Expired); err != nil {
		return report, err
	}
	p := backupKeysCleanupPlan{1, "expired_keys_only", input, output, dev, inode, domain.Time(clock().UnixNano()), sha256.Sum256(trustRaw), sha256.Sum256(raw), bundle}
	seed, err := readPrivate(filepath.Join(cfg.DataDir, "keys/evidence-000010.seed"), ed25519.SeedSize)
	if err != nil {
		return report, err
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return report, errors.New("invalid evidence signing seed")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	if !ed25519.PublicKey(marker.SigningPublic[:]).Equal(private.Public()) {
		return report, errors.New("plan signing key does not match trust")
	}
	encoded, err := encodeBackupKeysPlan(p, private)
	if err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = writeNew(output, encoded); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(filepath.Dir(output)); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	report.Planned = true
	return report, nil
}

// backupKeysPlanPaths は回収するrootから計画と信頼根を分離し、同じfileへの上書きを拒否する。
func backupKeysPlanPaths(input, trust, plan string) error {
	for _, pair := range [][2]string{{input, trust}, {input, plan}, {trust, plan}} {
		if e := separateBackupPaths(pair[0], pair[1]); e != nil {
			return e
		}
	}
	return nil
}

func backupKeysReclaimReport(m backupKeysManifest, now time.Time) BackupReport {
	report := BackupReport{ID: m.Backup, Expires: m.Expires, Files: len(m.Files), Expired: now.UnixNano() >= int64(m.Expires)}
	for _, f := range m.Files {
		report.Bytes += domain.U64(f.Length)
	}
	return report
}
