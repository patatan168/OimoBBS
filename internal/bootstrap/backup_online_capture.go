// オンライン集約を用途別認証manifest・外部回収計画・別保管鍵束・隔離再生へ接続する。
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
)

// OnlineBackupPreparationOptions は全サイト捕捉上限と別保管の信頼根・本文部分/鍵束部分/完成ペア計画。
// 各計画は新規file、本文・鍵束・作業先は分離したprivate配置を指定する。
type OnlineBackupPreparationOptions struct {
	CleanupKey                                            string
	Capture                                               OnlineBackupSiteOptions
	TrustInstance, PartialPlan, PartialKeysPlan, PairPlan string
}

// CaptureOnlineBackup は稼働正本から認証済み候補を作る。事前の監査移管完了を必要とする。
// 未有効化は形式2、有効化済みHTTPログの署名除外説明がある場合は形式4を使う。
// 本文前に外部署名予定集合を保存する。公開復元は許可しない。
func (r *Repository) CaptureOnlineBackup(ctx context.Context, output, trust, plan string, options OnlineBackupSiteOptions) (report BackupReport, err error) {
	return r.captureOnlineBackup(ctx, output, trust, plan, options, time.Now, func(string) error { return nil })
}
func (r *Repository) captureOnlineBackup(ctx context.Context, output, trust, plan string, options OnlineBackupSiteOptions, clock func() time.Time, checkpoint func(string) error) (report BackupReport, err error) {
	signer, e := r.preparePartialBackupSigner(output, trust, plan)
	if e != nil {
		return report, e
	}
	defer clear(signer.key)
	backupID := domain.NewID()
	var install func(func() error) error
	_, err = r.assembleOnlineBackupWithSetup(ctx, output, options, clock, checkpoint, func(cut OnlineBackupSiteCapture) error {
		m, e := onlineCaptureManifest(cut, backupID)
		if e != nil {
			return e
		}
		report, e = validateBackupManifest(m)
		if e != nil {
			return e
		}
		if e = verifyBackupFiles(ctx, output, m, false); e != nil {
			return e
		}
		key, e := backupKey(r.cfg.DataDir)
		if e != nil {
			return e
		}
		defer clear(key[:])
		raw, e := encodeBackupManifest(m, key)
		if e != nil {
			return e
		}
		if e = backupWindow(clock, m.Created, m.Expires); e != nil {
			return e
		}
		if e = writeNew(filepath.Join(output, "manifest.pending"), raw); e != nil {
			return e
		}
		if e = checkpoint("manifest_synced"); e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = backupWindow(clock, m.Created, m.Expires); e != nil {
			return e
		}
		if e = install(func() error {
			if e = os.Rename(filepath.Join(output, "manifest.pending"), filepath.Join(output, "manifest.json")); e != nil {
				return e
			}
			if e = store.SyncDirectory(output); e != nil {
				return e
			}
			if e = store.SyncDirectory(filepath.Dir(output)); e != nil {
				return e
			}
			return nil
		}); e != nil {
			return e
		}
		report.Verified = true
		return nil
	}, func(g *OnlineBackupGroup, started time.Time) error {
		install = g.install
		g.prefix = "owners"
		if g.optionalLogActive {
			raw, e := encodeBackupOptionalOmission(backupID, g.metadataOwner, g.optionalSiteSequence, g.metadataAt, signer.key)
			if e != nil {
				return e
			}
			if uint64(len(raw)) > g.metadataByteLimit-g.bytes {
				return store.ErrBackupPinBudget
			}
			g.metadata[backupOptionalOmissionName] = raw
			g.bytes += uint64(len(raw))
		}
		if len(g.requiredHoldBoards) > 0 {
			raw, e := encodeBackupRequiredOmission(backupID, g.metadataOwner, g.optionalSiteSequence, g.metadataAt, g.requiredHoldBoards, signer.key)
			if e != nil {
				return e
			}
			if uint64(len(raw)) > g.metadataByteLimit-g.bytes {
				return store.ErrBackupPinBudget
			}
			g.metadata[backupRequiredOmissionName] = raw
			g.bytes += uint64(len(raw))
		}
		g.beforeCopy = func() error {
			if e := signer.saveOnline(ctx, g, g.metadataOwner, started); e != nil {
				return e
			}
			return checkpoint("online_plan_synced")
		}
		return nil
	})
	if err != nil {
		report.Verified = false
	}
	return report, err
}

func onlineCaptureManifest(cut OnlineBackupSiteCapture, id domain.ID) (backupManifest, error) {
	m := backupManifest{DeletionReportsOmitted: cut.DeletionReportsOmitted, Schema: 7, Mode: "online_candidate", ID: id, Site: cut.Site, Created: cut.Started, Expires: cut.Expires, MinimumReader: cut.MinimumReader, KeyIDs: []uint32{1, 10}, Entries: []backupEntry{}, ControlCut: []backupCut{}}
	for _, c := range cut.Captures {
		entry := backupEntry{Kind: c.Kind, Owner: c.Owner, Subkey: c.Subkey, Captured: c.CapturedAt, Sequence: c.Capture.Sequence, RequiredEnd: c.Capture.RequiredEnd, OriginalExpires: c.Capture.Expires, Files: []backupFile{}}
		for _, f := range c.Capture.Files {
			entry.Files = append(entry.Files, backupFile{f.Name, f.Length, f.SHA})
			if c.Kind == "metadata" && f.Name == backupRequiredOmissionName {
				m.RequiredHoldsOmitted = true
			}
			if c.Kind == "metadata" && f.Name == backupOptionalOmissionName {
				m.OptionalHTTPLogsOmitted = true
			}
		}
		if len(c.Capture.Current) > 0 {
			entry.Files = append(entry.Files, backupFile{c.Capture.CurrentName, domain.U64(len(c.Capture.Current)), sha256.Sum256(c.Capture.Current)})
		}
		m.Entries = append(m.Entries, entry)
		if c.Kind == "site" || c.Kind == "board" {
			m.ControlCut = append(m.ControlCut, backupCut{c.Kind, c.Owner, c.Capture.Sequence})
		}
	}
	_, err := validateBackupManifest(m)
	return m, err
}

// PrepareOnlineBackup は稼働Repositoryを閉じず、本文/鍵束/回収計画/隔離再生まで一括実行する。
// 完成済み出力を失敗時に消さず、各工程の結果と全体完了を区別する。
func (r *Repository) PrepareOnlineBackup(ctx context.Context, output, keys, work string, options OnlineBackupPreparationOptions) (report BackupPreparationReport, err error) {
	report.Phase = "preflight"
	if options.CleanupKey != "" {
		if err = validateIndependentCleanupPaths(options.CleanupKey, r.cfg.DataDir, output, keys, work, options.TrustInstance, options.PartialPlan, options.PartialKeysPlan, options.PairPlan); err != nil {
			return report, err
		}
	}
	defer func() {
		if err != nil {
			report.Complete = false
		}
	}()
	plans := &backupPartialPreparation{trust: options.TrustInstance, plan: options.PartialPlan, keysPlan: options.PartialKeysPlan, pairPlan: options.PairPlan}
	if plans.plan == "" || plans.keysPlan == "" || plans.pairPlan == "" {
		return report, errors.New("online preparation requires body/keys partial and pair plans")
	}
	if err = r.backupPreparationPaths(output, keys, work); err != nil {
		return report, err
	}
	if err = plans.preparationPaths(output, keys, work); err != nil {
		return report, err
	}
	// 完成ペアへ本文のオンライン予定集合を登録するのは別用途のため、配置だけ共通検査する。
	keysSigner, e := r.preparePartialBackupSigner(keys, plans.trust, plans.keysPlan)
	if e != nil {
		return report, e
	}
	defer clear(keysSigner.key)
	pairSigner, e := r.preparePartialBackupSigner(keys, plans.trust, plans.pairPlan)
	if e != nil {
		return report, e
	}
	clear(pairSigner.key)
	unlock, e := lockBackupDirectories(filepath.Dir(output), filepath.Dir(keys), work)
	if e != nil {
		return report, e
	}
	defer func() {
		err = errors.Join(err, unlock())
		if err != nil {
			report.Complete = false
		}
	}()
	report.PartialPlanned = new(bool)
	report.KeysPartialPlanned = new(bool)
	report.PairPlanned = new(bool)
	report.Phase = "capture"
	capture, e := r.captureOnlineBackup(ctx, output, plans.trust, plans.plan, options.Capture, time.Now, func(stage string) error {
		if stage == "online_plan_synced" {
			*report.PartialPlanned = true
		}
		return nil
	})
	if capture.ID != (domain.ID{}) {
		report.Capture = &capture
	}
	if e != nil {
		return report, e
	}
	report.Phase = "keys"
	bundle, e := r.exportBackupKeysWithSetup(ctx, output, keys, time.Now, func(string) {}, func(m backupKeysManifest, raw []byte) error {
		if err := keysSigner.saveKeys(ctx, m, raw); err != nil {
			return err
		}
		*report.KeysPartialPlanned = true
		return nil
	})
	if bundle.ID != (domain.ID{}) {
		report.Keys = &bundle
	}
	if e != nil {
		return report, e
	}
	report.Phase = "pair_plan"
	pair, e := r.planBackupPairReclamationWithPlans(ctx, output, keys, plans.trust, plans.pairPlan, BackupPairRelatedPlans{PartialKeysPlan: plans.keysPlan}, time.Now)
	report.PairPlan = &pair
	if e != nil {
		return report, e
	}
	*report.PairPlanned = pair.Planned
	// 完成ペア計画同期後、オンライン本文の事前計画を使用済みにする。
	planRaw, e := readPrivate(plans.plan, backupPartialPlanLimit)
	if e != nil {
		return report, e
	}
	if e = retireBackupCleanupPlan(plans.plan, planRaw, backupPartialPlanLimit); e != nil {
		return report, e
	}
	report.Phase = "replay"
	replay, e := verifyBackupReplayIndependent(ctx, output, keys, work, options.CleanupKey, time.Now, func(string) error { return nil })
	if replay.ID != (domain.ID{}) {
		report.Replay = &replay
	}
	if e != nil {
		return report, e
	}
	if e = ctx.Err(); e != nil {
		return report, e
	}
	report.Phase = "complete"
	report.Complete = true
	return report, nil
}
