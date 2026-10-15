// 完成本文と鍵束の保存先・認証manifestを一つの用途別署名へ束縛する。
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

const backupPairPlanLimit = backupManifestLimit + (128 << 10)

type backupPairPlan struct {
	Schema uint32                   `json:"schema"`
	Mode   string                   `json:"mode"`
	Body   backupPartialCleanupPlan `json:"body"`
	Keys   backupKeysCleanupPlan    `json:"keys"`
}

type backupPairEnvelope struct {
	Plan         json.RawMessage `json:"plan"`
	SHA          domain.Hash     `json:"plan_sha256"`
	SigningKeyID uint32          `json:"signing_key_id"`
	Signature    string          `json:"signature"`
	Retired      bool            `json:"retired"`
	BodyRetired  bool            `json:"body_retired"`
}

// BackupPairReport は認証・工程別回収結果。削除済み判定と全工程成功を区別する。
// Body/Keysは認証後だけ付け、秘密鍵・本文・保存先は出力しない。
type BackupPairReport struct {
	RelatedPlanCount    *int          `json:"related_plan_count,omitempty"`
	RelatedRetiredCount *int          `json:"related_retired_count,omitempty"`
	Phase               string        `json:"phase"`
	Body                *BackupReport `json:"body,omitempty"`
	Keys                *BackupReport `json:"keys,omitempty"`
	Planned             bool          `json:"planned"`
	Expired             bool          `json:"expired"`
	BodyRemoved         bool          `json:"body_removed"`
	KeysRemoved         bool          `json:"keys_removed"`
	Applied             bool          `json:"applied"`
	RestoreReady        bool          `json:"restore_ready"`
}

// PlanBackupPairReclamation は停止中正本に対応する完成本文/鍵束を全照合して回収計画を新規保存する。
// 期限を延長せず、二つのrootのdevice/inodeと元manifestを署名へ含める。
func PlanBackupPairReclamation(ctx context.Context, cfg Config, body, keys, trust, plan string) (BackupPairReport, error) {
	return planBackupPairReclamation(ctx, cfg, body, keys, trust, plan, time.Now)
}

// PlanBackupPairReclamationWithPlans は対応する既存計画を完成ペア署名へ登録する。
// 登録済み計画は回収時に全件認証し、両出力の除去前に使用済み化する。
func PlanBackupPairReclamationWithPlans(ctx context.Context, cfg Config, body, keys, trust, plan string, related BackupPairRelatedPlans) (BackupPairReport, error) {
	return planBackupPairReclamationWithPlans(ctx, cfg, body, keys, trust, plan, related, time.Now)
}

func planBackupPairReclamation(ctx context.Context, cfg Config, body, keys, trust, plan string, clock func() time.Time) (report BackupPairReport, err error) {
	return planBackupPairReclamationWithPlans(ctx, cfg, body, keys, trust, plan, BackupPairRelatedPlans{}, clock)
}

func planBackupPairReclamationWithPlans(ctx context.Context, cfg Config, body, keys, trust, plan string, related BackupPairRelatedPlans, clock func() time.Time) (report BackupPairReport, err error) {
	report.Phase = "preflight"
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = backupPairPaths(body, keys, trust, plan); err != nil {
		return report, err
	}
	unlock, err := lockBackupPairParents(body, keys)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	r, err := openBackupRepository(cfg)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	return r.planBackupPairReclamationWithPlans(ctx, body, keys, trust, plan, related, clock)
}

// planBackupPairReclamation は呼出元の正本/出力親排他下で完成ペアを署名する。
func (r *Repository) planBackupPairReclamation(ctx context.Context, body, keys, trust, plan string, clock func() time.Time) (report BackupPairReport, err error) {
	return r.planBackupPairReclamationWithPlans(ctx, body, keys, trust, plan, BackupPairRelatedPlans{}, clock)
}

// planBackupPairReclamationWithPlans は既存の関連計画も同じ完成ペアへ署名登録する。
func (r *Repository) planBackupPairReclamationWithPlans(ctx context.Context, body, keys, trust, plan string, related BackupPairRelatedPlans, clock func() time.Time) (report BackupPairReport, err error) {
	report.Phase = "preflight"
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = backupPairPaths(body, keys, trust, plan); err != nil {
		return report, err
	}
	cfg := r.cfg
	for _, path := range []string{body, keys, trust, plan} {
		if err = r.candidatePath(path); err != nil {
			return report, err
		}
	}
	marker, trustRaw, err := loadBackupTrust(trust)
	if err != nil {
		return report, err
	}
	source, sourceRaw, err := loadBackupTrust(filepath.Join(cfg.DataDir, "instance.json"))
	if err != nil {
		return report, err
	}
	if marker != source || sha256.Sum256(trustRaw) != sha256.Sum256(sourceRaw) {
		return report, errors.New("pair plan trust does not match source")
	}
	m, br, err := r.loadBackup(body)
	if err != nil {
		return report, err
	}
	if err = verifyBackupFiles(ctx, body, m, true); err != nil {
		return report, err
	}
	bundle, err := loadBackupKeys(ctx, keys)
	if err != nil {
		return report, err
	}
	bodyRaw, err := readPrivate(filepath.Join(body, "manifest.json"), backupManifestLimit)
	if err != nil {
		return report, err
	}
	keyRaw, err := readPrivate(filepath.Join(keys, "bundle.json"), backupKeysLimit)
	if err != nil {
		return report, err
	}
	bd, bi, err := replayRootIdentity(body)
	if err != nil {
		return report, err
	}
	kd, ki, err := replayRootIdentity(keys)
	if err != nil {
		return report, err
	}
	trustSHA := sha256.Sum256(trustRaw)
	p := backupPairPlan{1, "expired_body_then_keys", backupPartialCleanupPlan{1, "expired_partial_copy_only", body, plan, bd, bi, trustSHA, sha256.Sum256(bodyRaw), domain.U64(len(bodyRaw)), m}, backupKeysCleanupPlan{1, "expired_keys_only", keys, plan, kd, ki, domain.Time(clock().UnixNano()), trustSHA, sha256.Sum256(keyRaw), bundle}}
	if err = validateBackupPairPlan(p); err != nil {
		return report, err
	}
	if err = matchBackupInstance(m, bundle.Files[0].SHA); err != nil {
		return report, err
	}
	refs, err := related.relatedPaths(body, keys, trust, plan)
	if err != nil {
		return report, err
	}
	for _, ref := range refs {
		if err = r.candidatePath(ref.Path); err != nil {
			return report, err
		}
	}
	states, err := loadPairRelatedPlans(ctx, p, refs, marker, trustRaw, trust, false)
	if err != nil {
		return report, err
	}
	for i := range states {
		refs[i] = states[i].ref
	}
	if len(refs) > 0 {
		if err = validateRelatedRefs(p, refs); err != nil {
			return report, err
		}
		count := len(refs)
		report.RelatedPlanCount = &count
		report.RelatedRetiredCount = new(int)
	}
	report.Body = &br
	kr := backupKeysReclaimReport(bundle, clock())
	br.Expired = kr.Expired
	report.Keys = &kr
	report.Expired = kr.Expired
	seed, err := readPrivate(filepath.Join(cfg.DataDir, "keys/evidence-000010.seed"), ed25519.SeedSize)
	if err != nil {
		return report, err
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return report, errors.New("invalid pair signing seed")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	if !ed25519.PublicKey(marker.SigningPublic[:]).Equal(private.Public()) {
		return report, errors.New("pair signing key mismatch")
	}
	raw, err := encodeBackupPairPayload(p, refs)
	if err != nil {
		return report, err
	}
	hash := sha256.Sum256(raw)
	env := backupPairEnvelope{raw, hash, 10, base64.StdEncoding.EncodeToString(ed25519.Sign(private, backupPairPayloadMessage(hash))), false, false}
	encoded, err := json.Marshal(env)
	if err != nil {
		return report, err
	}
	if len(encoded) > backupPairPlanLimit {
		return report, errors.New("pair plan budget exceeded")
	}
	report.Phase = "plan"
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = writeNew(plan, encoded); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(filepath.Dir(plan)); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	report.Planned = true
	report.Phase = "complete"
	return report, nil
}

func backupPairMessage(hash domain.Hash) []byte {
	return append([]byte("oimo/backup-pair-cleanup/v1\x00"), hash[:]...)
}

// validateBackupPairPlan は再利用したroot記述を完成ペア用途として照合する。
func validateBackupPairPlan(p backupPairPlan) error {
	if p.Schema != 1 || p.Mode != "expired_body_then_keys" {
		return errors.New("invalid pair cleanup purpose")
	}
	if e := validateBackupPartialPlan(p.Body); e != nil {
		return e
	}
	if e := validateBackupKeysPlan(p.Keys); e != nil {
		return e
	}
	b, k := p.Body.Manifest, p.Keys.Bundle
	if p.Body.Plan != p.Keys.Plan || p.Body.TrustSHA != p.Keys.TrustSHA || !backupKeysBindingMatches(b, k) || p.Body.ManifestSHA != k.BackupSHA {
		return errors.New("pair cleanup binding mismatch")
	}
	return matchBackupInstance(b, k.Files[0].SHA)
}

// encodeBackupPairPayload は関連計画なしの空配列も含め、現行v3だけで保存する。
func encodeBackupPairPayload(p backupPairPlan, refs []backupPairRelatedRef) ([]byte, error) {
	if refs == nil {
		refs = []backupPairRelatedRef{}
	}
	return json.Marshal(backupPairPlanV2{3, p.Mode, p.Body, p.Keys, refs})
}
func backupPairPayloadMessage(hash domain.Hash) []byte {
	return append([]byte("oimo/backup-pair-cleanup/v3\x00"), hash[:]...)
}

func decodeBackupPairPlan(raw []byte, trust instance, trustRaw []byte) (backupPairPlan, backupPairEnvelope, error) {
	p, _, env, e := decodeBackupPairPlanRelated(raw, trust, trustRaw)
	return p, env, e
}

func decodeBackupPairPlanRelated(raw []byte, trust instance, trustRaw []byte) (p backupPairPlan, refs []backupPairRelatedRef, env backupPairEnvelope, err error) {
	if len(raw) > backupPairPlanLimit {
		return p, refs, env, errors.New("pair plan budget exceeded")
	}
	if err = strictjson.Decode(raw, &env); err != nil {
		return p, refs, env, err
	}
	if env.Retired {
		return p, refs, env, errors.New("pair plan retired; inspect remaining empty key root")
	}
	var current backupPairPlanV2
	if err = strictjson.Decode(env.Plan, &current); err != nil {
		return p, refs, env, err
	}
	if current.Schema != 3 || current.Related == nil {
		return p, refs, env, errors.New("unsupported pair plan schema")
	}
	p = backupPairPlan{1, current.Mode, current.Body, current.Keys}
	refs = current.Related
	if len(refs) > 0 {
		if err = validateRelatedRefs(p, refs); err != nil {
			return p, refs, env, err
		}
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != env.Signature || env.SigningKeyID != 10 || sha256.Sum256(env.Plan) != env.SHA || !ed25519.Verify(ed25519.PublicKey(trust.SigningPublic[:]), backupPairPayloadMessage(env.SHA), sig) {
		return p, refs, env, errors.New("pair plan signature mismatch")
	}
	if err = validateBackupPairPlan(p); err != nil {
		return p, refs, env, err
	}
	if p.Body.TrustSHA != sha256.Sum256(trustRaw) || p.Body.Manifest.Site != trust.SiteID {
		return p, refs, env, errors.New("pair plan trust mismatch")
	}
	return p, refs, env, nil
}

func backupPairPaths(body, keys, trust, plan string) error {
	paths := []string{body, keys, trust, plan}
	for i, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("pair cleanup requires clean absolute paths")
		}
		for _, other := range paths[:i] {
			if e := separateBackupPaths(path, other); e != nil {
				return e
			}
		}
	}
	return nil
}
