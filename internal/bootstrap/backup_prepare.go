// 停止中コピーと鍵束を同じ排他下で作り、正本を閉じた後に隔離再生まで完了する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
)

// BackupPreparationReport は工程別の結果。Completeだけが全工程の成功を示す。
type BackupPreparationReport struct {
	PairPlanned        *bool                 `json:"pair_planned,omitempty"`
	PairPlan           *BackupPairReport     `json:"pair_plan,omitempty"`
	KeysPlanned        *bool                 `json:"keys_planned,omitempty"`
	KeysPlan           *BackupKeysPlanReport `json:"keys_plan,omitempty"`
	KeysPartialPlanned *bool                 `json:"keys_partial_planned,omitempty"`
	PartialPlanned     *bool                 `json:"partial_planned,omitempty"`
	Phase              string                `json:"phase"`
	Capture            *BackupReport         `json:"capture,omitempty"`
	Keys               *BackupReport         `json:"keys,omitempty"`
	Replay             *BackupReport         `json:"replay,omitempty"`
	Complete           bool                  `json:"complete"`
	RestoreReady       bool                  `json:"restore_ready"`
}

// PrepareOfflineBackup は新規コピー・別保管鍵の作成と隔離再生を一括して実行する。
// 既存出力を上書きせず、失敗時の出力も残す。workParentは既存0700の専用親。
func PrepareOfflineBackup(ctx context.Context, cfg Config, output, keysOutput, workParent string) (BackupPreparationReport, error) {
	return prepareOfflineBackup(ctx, cfg, output, keysOutput, workParent, time.Now, func(string) error { return nil })
}

func prepareOfflineBackup(ctx context.Context, cfg Config, output, keysOutput, workParent string, clock func() time.Time, checkpoint func(string) error) (report BackupPreparationReport, err error) {
	return prepareOfflineBackupWithPlan(ctx, cfg, output, keysOutput, workParent, nil, clock, checkpoint)
}

// backupPartialPreparation は任意の事前/完成署名計画の配置。nilなら従来の出力契約を維持する。
type backupPartialPreparation struct{ trust, plan, keysPlan, completePlan, pairPlan string }

// PreparePlannedOfflineBackup は本文の事前署名計画を一括作成と同じ正本排他へ接続する。
// trust/planは本文・鍵束・作業親・正本の外へ置く。回収対象は未完成本文だけ。
func PreparePlannedOfflineBackup(ctx context.Context, cfg Config, output, keysOutput, workParent, trust, plan string) (BackupPreparationReport, error) {
	return prepareOfflineBackupWithPlan(ctx, cfg, output, keysOutput, workParent, &backupPartialPreparation{trust: trust, plan: plan}, time.Now, func(string) error { return nil })
}

// PrepareOfflineBackupWithPlans は本文と鍵束の両事前計画を同じ正本排他へ接続する。
// 両計画は出力/作業親の外へ置き、本文完成後の失敗でも完成本文を保持する。
func PrepareOfflineBackupWithPlans(ctx context.Context, cfg Config, output, keysOutput, workParent, trust, plan, keysPlan string) (BackupPreparationReport, error) {
	if keysPlan == "" {
		return BackupPreparationReport{Phase: "preflight", PartialPlanned: new(bool), KeysPartialPlanned: new(bool)}, errors.New("keys partial plan is required")
	}
	return prepareOfflineBackupWithPlan(ctx, cfg, output, keysOutput, workParent, &backupPartialPreparation{trust: trust, plan: plan, keysPlan: keysPlan}, time.Now, func(string) error { return nil })
}

// BackupPreparationPlans は任意の本文/鍵束事前計画・完成鍵束計画・完成ペア計画の配置。
// TrustInstanceは計画指定時に必須。PartialKeysPlanはPartialPlanとの併用だけを許す。
type BackupPreparationPlans struct {
	TrustInstance   string
	PartialPlan     string
	PartialKeysPlan string
	KeysPlan        string
	PairPlan        string
}

// PrepareOfflineBackupPlanned は指定した計画を出力前に検査し、同じ正本排他下で一括保存する。
// 完成計画は両出力完成後、正本Close/隔離再生前に同期する。PairPlan指定時は両出力親を排他する。
func PrepareOfflineBackupPlanned(ctx context.Context, cfg Config, output, keysOutput, workParent string, plans BackupPreparationPlans) (BackupPreparationReport, error) {
	partial := &backupPartialPreparation{trust: plans.TrustInstance, plan: plans.PartialPlan, keysPlan: plans.PartialKeysPlan, completePlan: plans.KeysPlan, pairPlan: plans.PairPlan}
	return prepareOfflineBackupWithPlan(ctx, cfg, output, keysOutput, workParent, partial, time.Now, func(string) error { return nil })
}

// prepareOfflineBackupWithPlan は計画付き/従来一括作成でClose・再生・完了判定を共有する。
func prepareOfflineBackupWithPlan(ctx context.Context, cfg Config, output, keysOutput, workParent string, partial *backupPartialPreparation, clock func() time.Time, checkpoint func(string) error) (report BackupPreparationReport, err error) {
	if partial != nil {
		if partial.pairPlan != "" {
			report.PairPlanned = new(bool)
		}
		if partial.plan != "" || (partial.completePlan == "" && partial.pairPlan == "") {
			report.PartialPlanned = new(bool)
		}
		if partial.completePlan != "" {
			report.KeysPlanned = new(bool)
		}
		if partial.keysPlan != "" {
			report.KeysPartialPlanned = new(bool)
		}
	}
	report.Phase = "source_open"
	if err = ctx.Err(); err != nil {
		return report, err
	}
	r, err := openBackupRepository(cfg)
	if err != nil {
		return report, err
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, r.Close())
		}
		if err != nil {
			report.Complete = false
		}
	}()
	if partial != nil && partial.pairPlan != "" {
		report.Phase = "preflight"
		if err = r.backupPreparationPaths(output, keysOutput, workParent); err != nil {
			return report, err
		}
		if err = partial.preparationPaths(output, keysOutput, workParent); err != nil {
			return report, err
		}
		unlock, e := lockBackupDirectories(filepath.Dir(output), filepath.Dir(keysOutput), workParent)
		if e != nil {
			return report, e
		}
		defer func() { err = errors.Join(err, unlock()) }()
	}
	if err = r.prepareBackupArtifactsWithPlan(ctx, output, keysOutput, workParent, partial, clock, checkpoint, &report); err != nil {
		return report, err
	}
	report.Phase = "source_close"
	err = r.Close()
	closed = true
	if err != nil {
		return report, err
	}
	if err = checkpoint("source_closed"); err != nil {
		return report, err
	}
	report.Phase = "replay"
	replay, err := verifyBackupReplay(ctx, output, keysOutput, workParent, clock, func(string) error { return nil })
	if replay.ID != (domain.ID{}) {
		report.Replay = &replay
	}
	if err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if clock().UnixNano() >= int64(replay.Expires) {
		return report, errors.New("backup expired before preparation completion")
	}
	report.Phase = "complete"
	report.Complete = true
	return report, nil
}

// prepareBackupArtifacts は正本排他下の工程をまとめ、完了/失敗した工程だけ結果へ記録する。
func (r *Repository) prepareBackupArtifacts(ctx context.Context, output, keys, work string, clock func() time.Time, checkpoint func(string) error, report *BackupPreparationReport) error {
	return r.prepareBackupArtifactsWithPlan(ctx, output, keys, work, nil, clock, checkpoint, report)
}

// prepareBackupArtifactsWithPlan は全配置を先に検査し、事前計画はpayload前、完成計画は両出力後に保存する。
func (r *Repository) prepareBackupArtifactsWithPlan(ctx context.Context, output, keys, work string, partial *backupPartialPreparation, clock func() time.Time, checkpoint func(string) error, report *BackupPreparationReport) error {
	report.Phase = "preflight"
	if e := r.backupPreparationPaths(output, keys, work); e != nil {
		return e
	}
	setup := func(backupManifest, []byte) error { return nil }
	keysSetup := func(backupKeysManifest, []byte) error { return nil }
	if partial != nil {
		if e := partial.preparationPaths(output, keys, work); e != nil {
			return e
		}
		for _, complete := range []string{partial.completePlan, partial.pairPlan} {
			if complete == "" {
				continue
			}
			signer, e := r.preparePartialBackupSigner(keys, partial.trust, complete)
			if e != nil {
				return e
			}
			clear(signer.key)
		}
		if partial.keysPlan != "" {
			keysSigner, e := r.preparePartialBackupSigner(keys, partial.trust, partial.keysPlan)
			if e != nil {
				return e
			}
			defer clear(keysSigner.key)
			keysSetup = func(m backupKeysManifest, raw []byte) error {
				if e := keysSigner.saveKeys(ctx, m, raw); e != nil {
					return e
				}
				*report.KeysPartialPlanned = true
				return checkpoint("keys_partial_plan_synced")
			}
		}
		if partial.plan != "" {
			signer, e := r.preparePartialBackupSigner(output, partial.trust, partial.plan)
			if e != nil {
				return e
			}
			defer clear(signer.key)
			setup = func(m backupManifest, raw []byte) error {
				if e := signer.save(ctx, m, raw); e != nil {
					return e
				}
				*report.PartialPlanned = true
				return checkpoint("partial_plan_synced")
			}
		}
	}
	report.Phase = "capture"
	capture, e := r.captureOfflineBackupWithSetup(ctx, output, clock, func(string) {}, setup)
	if capture.ID != (domain.ID{}) {
		report.Capture = &capture
	}
	if e != nil {
		return e
	}
	if e = checkpoint("capture_complete"); e != nil {
		return e
	}
	report.Phase = "keys"
	bundle, e := r.exportBackupKeysWithSetup(ctx, output, keys, clock, func(string) {}, keysSetup)
	if bundle.ID != (domain.ID{}) {
		report.Keys = &bundle
	}
	if e != nil {
		return e
	}
	if e = checkpoint("keys_complete"); e != nil {
		return e
	}
	if e = r.prepareCompleteKeysPlan(ctx, keys, partial, clock, checkpoint, report); e != nil {
		return e
	}
	return r.preparePairPlan(ctx, output, keys, partial, clock, checkpoint, report)
}

// prepareCompleteKeysPlan は完成鍵束の署名計画だけを保存し、同期後の工程を報告する。
func (r *Repository) prepareCompleteKeysPlan(ctx context.Context, keys string, partial *backupPartialPreparation, clock func() time.Time, checkpoint func(string) error, report *BackupPreparationReport) error {
	if partial == nil || partial.completePlan == "" {
		return nil
	}
	report.Phase = "keys_plan"
	planned, e := r.planBackupKeysReclamation(ctx, keys, partial.trust, partial.completePlan, clock)
	if planned.Backup != nil {
		report.KeysPlan = &planned
	}
	if e != nil {
		return e
	}
	*report.KeysPlanned = planned.Planned
	return checkpoint("keys_plan_synced")
}

// preparePairPlan は本文/鍵束完成後の署名計画保存を全体完了と区別して報告する。
func (r *Repository) preparePairPlan(ctx context.Context, body, keys string, plans *backupPartialPreparation, clock func() time.Time, checkpoint func(string) error, report *BackupPreparationReport) error {
	if plans == nil || plans.pairPlan == "" {
		return nil
	}
	report.Phase = "pair_plan"
	planned, e := r.planBackupPairReclamationWithPlans(ctx, body, keys, plans.trust, plans.pairPlan, BackupPairRelatedPlans{PartialPlan: plans.plan, PartialKeysPlan: plans.keysPlan, KeysPlan: plans.completePlan}, clock)
	if planned.Body != nil {
		report.PairPlan = &planned
	}
	if e != nil {
		return e
	}
	*report.PairPlanned = planned.Planned
	return checkpoint("pair_plan_synced")
}

// backupPreparationPaths は全工程の配置を先に検査し、不正な鍵/作業先でコピーを作らない。
func (r *Repository) backupPreparationPaths(output, keys, work string) error {
	paths := []string{r.cfg.DataDir, output, keys, work}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if e := separateBackupPaths(paths[i], paths[j]); e != nil {
				return e
			}
		}
	}
	for _, p := range []string{output, keys} {
		if e := r.candidatePath(p); e != nil {
			return e
		}
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			return errors.New("backup preparation requires new output directories")
		}
	}
	if e := privatePath(filepath.Dir(work), true); e != nil {
		return e
	}
	return privatePath(work, true)
}

// preparationPaths は署名計画/信頼根を鍵束と隔離作業の除去範囲からも分離する。
func (p backupPartialPreparation) preparationPaths(output, keys, work string) error {
	if p.trust == "" || (p.plan == "" && p.completePlan == "" && p.pairPlan == "") || (p.keysPlan != "" && p.plan == "") {
		return errors.New("planned preparation requires trust and plan")
	}
	if p.pairPlan != "" {
		related := BackupPairRelatedPlans{PartialPlan: p.plan, PartialKeysPlan: p.keysPlan, KeysPlan: p.completePlan}
		if _, e := related.relatedPaths(output, keys, p.trust, p.pairPlan); e != nil {
			return e
		}
	}
	paths := []string{output, keys, work, p.trust}
	for _, plan := range []string{p.plan, p.keysPlan, p.completePlan, p.pairPlan} {
		if plan != "" {
			paths = append(paths, plan)
		}
	}
	for i, a := range paths {
		for _, b := range paths[i+1:] {
			if e := separateBackupPaths(a, b); e != nil {
				return e
			}
		}
	}
	return nil
}
