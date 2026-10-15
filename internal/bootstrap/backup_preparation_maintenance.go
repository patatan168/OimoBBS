// 停止中の定期バックアップ作成を、固定親・新規名・全回収計画・隔離再生へ接続する。
package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"oimobbs/internal/domain"
)

// BackupPreparationMaintenanceOptions は別々の専用0700親と公開信頼根、周期、時間上限。
// Apply=falseは配置確認のみ。稼働正本の停止や出力の自動回収は行わない。
type BackupPreparationMaintenanceOptions struct {
	CleanupKey                                                               string
	CopyParent, KeysParent                                                   string
	PartialPlanParent, PartialKeysPlanParent, KeysPlanParent, PairPlanParent string
	WorkParent, ControlParent, TrustInstance                                 string
	Interval, Budget                                                         time.Duration
	Apply                                                                    bool
	Reclaim                                                                  bool
}

// BackupPreparationMaintenanceReport は秘密/pathを含まない一回分の結果。
// Nameは同名出力/計画のbasename。CompleteはPreparationで判定する。
type BackupPreparationMaintenanceReport struct {
	Pass         domain.U64               `json:"pass"`
	Status       string                   `json:"status"`
	Apply        bool                     `json:"apply"`
	Name         string                   `json:"name,omitempty"`
	Preparation  *BackupPreparationReport `json:"preparation,omitempty"`
	RestoreReady bool                     `json:"restore_ready"`
	Cleanup      *OnlineBackupSweepReport `json:"cleanup,omitempty"`
}

type preparationMaintenanceIdentity struct {
	cleanupSHA domain.Hash
	roots      [9][2]domain.U64
	trustSHA   domain.Hash
}

func (o BackupPreparationMaintenanceOptions) parents() []string {
	return []string{o.CopyParent, o.KeysParent, o.PartialPlanParent, o.PartialKeysPlanParent, o.KeysPlanParent, o.PairPlanParent, o.WorkParent, o.ControlParent}
}

// validatePreparationMaintenance は正本・全親・信頼根の重複/内包と弱い所有権を拒否する。
func validatePreparationMaintenance(cfg Config, o BackupPreparationMaintenanceOptions) error {
	if e := cfg.validate(); e != nil {
		return e
	}
	if o.Budget < time.Second || o.Budget > time.Hour {
		return errors.New("preparation budget requires 1s..1h")
	}
	paths := append([]string{cfg.DataDir}, o.parents()...)
	paths = append(paths, o.TrustInstance)
	if o.CleanupKey != "" {
		if e := validateIndependentCleanupPaths(o.CleanupKey, paths...); e != nil {
			return e
		}
	}
	for i, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("preparation requires clean absolute paths")
		}
		for _, other := range paths[:i] {
			if e := separateBackupPaths(path, other); e != nil {
				return e
			}
		}
		if i < len(paths)-1 {
			if e := privatePath(path, true); e != nil {
				return e
			}
		}
	}
	_, _, e := loadBackupTrust(o.TrustInstance)
	return e
}

// preparationIdentity は正本と8親のdevice/inode、公開信頼根bytesを周期間で固定する。
func preparationIdentity(cfg Config, o BackupPreparationMaintenanceOptions) (v preparationMaintenanceIdentity, err error) {
	for i, parent := range append([]string{cfg.DataDir}, o.parents()...) {
		d, n, e := replayRootIdentity(parent)
		if e != nil {
			return v, e
		}
		v.roots[i] = [2]domain.U64{d, n}
	}
	_, raw, e := loadBackupTrust(o.TrustInstance)
	if e != nil {
		return v, e
	}
	v.trustSHA = sha256.Sum256(raw)
	if o.CleanupKey != "" {
		key, e := independentReplayKey(o.CleanupKey)
		if e != nil {
			return v, e
		}
		v.cleanupSHA = sha256.Sum256(key[:])
		clear(key[:])
	}
	return v, nil
}

// PrepareNextOfflineBackup は専用制御親を排他し、新規同名ペアと4計画を一括作成する。
// 正本/出力親がbusyなら出力を作らず延期する。途中失敗の出力は保持する。
func PrepareNextOfflineBackup(ctx context.Context, cfg Config, o BackupPreparationMaintenanceOptions) (report BackupPreparationMaintenanceReport, err error) {
	if o.CleanupKey != "" {
		return report, errors.New("independent cleanup key requires online preparation")
	}
	report.Status = "failed"
	report.Apply = o.Apply
	defer func() {
		if err != nil {
			report.Status = backupMaintenanceStatus(err)
		}
	}()
	if err = validatePreparationMaintenance(cfg, o); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	unlock, err := lockBackupDirectories(o.ControlParent)
	if err != nil {
		return report, err
	}
	defer func() {
		if e := unlock(); e != nil {
			err = errors.Join(err, e)
		}
	}()
	batch, cancel := context.WithTimeout(ctx, o.Budget)
	defer cancel()
	return prepareNextOfflineBackup(batch, cfg, o)
}

// prepareNextOfflineBackup は制御親排他下の工程。途中出力は別名へ移り、推測回収しない。
func prepareNextOfflineBackup(ctx context.Context, cfg Config, o BackupPreparationMaintenanceOptions) (report BackupPreparationMaintenanceReport, err error) {
	report.Status = "failed"
	report.Apply = o.Apply
	defer func() {
		if err != nil {
			report.Status = backupMaintenanceStatus(err)
		}
	}()
	if err = validatePreparationMaintenance(cfg, o); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = checkPreparationEntryLimits(ctx, o.parents()[:6]); err != nil {
		return report, err
	}
	if !o.Apply {
		report.Status = "preview"
		return report, nil
	}
	name, err := newPreparationName(o)
	if err != nil {
		return report, err
	}
	report.Name = name
	plans := BackupPreparationPlans{TrustInstance: o.TrustInstance, PartialPlan: filepath.Join(o.PartialPlanParent, name+".json"), PartialKeysPlan: filepath.Join(o.PartialKeysPlanParent, name+".json"), KeysPlan: filepath.Join(o.KeysPlanParent, name+".json"), PairPlan: filepath.Join(o.PairPlanParent, name+".json")}
	prepared, err := PrepareOfflineBackupPlanned(ctx, cfg, filepath.Join(o.CopyParent, name), filepath.Join(o.KeysParent, name), o.WorkParent, plans)
	report.Preparation = &prepared
	report.Status = backupMaintenanceStatus(err)
	if err == nil && !prepared.Complete {
		report.Status = "failed"
		return report, errors.New("preparation returned incomplete success")
	}
	if err != nil && prepared.Capture == nil && onlyPreparationBusy(err) {
		report.Status = "deferred_busy"
		return report, nil
	}
	return report, err
}

// checkPreparationEntryLimits は各親を有界列挙し、次の出力と.lock用に2entryを残す。
func checkPreparationEntryLimits(ctx context.Context, parents []string) error {
	for _, parent := range parents {
		f, e := os.Open(parent)
		if e != nil {
			return e
		}
		e = func() error {
			count := 0
			for {
				if e := ctx.Err(); e != nil {
					return e
				}
				entries, e := f.ReadDir(128)
				count += len(entries)
				if count > 4094 {
					return errors.New("preparation parent exceeds 4094 entries")
				}
				if e == io.EOF {
					return nil
				}
				if e != nil {
					return e
				}
			}
		}()
		e = errors.Join(e, f.Close())
		if e != nil {
			return e
		}
	}
	return nil
}

// newPreparationName は乱数128bit名を選び、既存root/計画との衝突を拒否する。
func newPreparationName(o BackupPreparationMaintenanceOptions) (string, error) {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", e
	}
	name := "backup-" + hex.EncodeToString(raw[:])
	for i, parent := range o.parents()[:6] {
		child := name
		if i >= 2 {
			child += ".json"
		}
		if _, e := os.Lstat(filepath.Join(parent, child)); !errors.Is(e, os.ErrNotExist) {
			return "", errors.New("preparation name collision or inaccessible target")
		}
	}
	return name, nil
}

type preparationMaintenanceFunc func(context.Context, Config, BackupPreparationMaintenanceOptions) (BackupPreparationMaintenanceReport, error)

// RunBackupPreparationMaintenance は即時実行後、完了から既定1時間の周期で新規組を作る。
// 親/信頼根変更・通常失敗・出力失敗で停止し、busy/時間切れは次回へ延期する。
func RunBackupPreparationMaintenance(ctx context.Context, cfg Config, o BackupPreparationMaintenanceOptions, emit func(BackupPreparationMaintenanceReport) error) error {
	if o.CleanupKey != "" {
		return errors.New("independent cleanup key requires online preparation")
	}
	return runBackupPreparationMaintenance(ctx, cfg, o, emit, waitReplayMaintenance, prepareNextOfflineBackup)
}

// runBackupPreparationMaintenance は待機/作成を注入できる周期処理。制御排他を終了まで保持する。
func runBackupPreparationMaintenance(ctx context.Context, cfg Config, o BackupPreparationMaintenanceOptions, emit func(BackupPreparationMaintenanceReport) error, wait func(context.Context, time.Duration) error, prepare preparationMaintenanceFunc) (err error) {
	if err = validatePreparationMaintenance(cfg, o); err != nil {
		return err
	}
	if o.Interval < time.Hour || o.Interval > 24*time.Hour || emit == nil || wait == nil || prepare == nil {
		return errors.New("preparation maintenance requires interval 1h..24h and callbacks")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	identity, err := preparationIdentity(cfg, o)
	if err != nil {
		return err
	}
	unlock, err := lockBackupDirectories(o.ControlParent)
	if err != nil {
		return err
	}
	defer func() {
		if e := unlock(); e != nil {
			err = errors.Join(err, e)
		}
	}()
	for pass := domain.U64(1); ; pass++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		current, e := preparationIdentity(cfg, o)
		if e != nil {
			return e
		}
		if current != identity {
			return errors.New("preparation source, parent or trust changed")
		}
		batch, cancel := context.WithTimeout(ctx, o.Budget)
		report, e := prepare(batch, cfg, o)
		cancel()
		report.Pass = pass
		if err = emit(report); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if report.Status == "failed" || report.Status == "interrupted" {
			return e
		}
		if err = wait(ctx, o.Interval); err != nil {
			return err
		}
	}
}

// onlyPreparationBusy はclose/syncなど別の失敗をbusy延期として隠さない。
func onlyPreparationBusy(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		leaves := joined.Unwrap()
		if len(leaves) == 0 {
			return false
		}
		for _, leaf := range leaves {
			if !onlyPreparationBusy(leaf) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyPreparationBusy(wrapped.Unwrap())
	}
	return err == syscall.EWOULDBLOCK || err == syscall.EAGAIN
}
