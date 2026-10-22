// 停止中に日別監査を作業領域へ原子的に移し、計画と一致する残存fileだけを回収する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/platform"
	"oimobbs/internal/store"
)

// ReclaimAuditDays は既定で対象を表示し、apply時だけ永続計画の下で回収する。
// 中断後は同じコマンドで再開する。必要な日別正本・投稿・evidenceは削除しない。
func ReclaimAuditDays(ctx context.Context, cfg Config, apply bool, capture func([]byte) error) (AuditReclaimReport, error) {
	return reclaimAuditDays(ctx, cfg, apply, capture, func(string) {})
}

func reclaimAuditDays(ctx context.Context, cfg Config, apply bool, capture func([]byte) error, checkpoint func(string)) (report AuditReclaimReport, err error) {
	if err = cfg.validate(); err != nil {
		return report, err
	}
	if err = cfg.checkTLS(time.Now()); err != nil {
		return report, err
	}
	if capture == nil {
		return report, errors.New("posting capture validator required")
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	work := filepath.Join(cfg.DataDir, auditReclaimIntent)
	exists := false
	if _, e := os.Lstat(work); e == nil {
		exists = true
	} else if !os.IsNotExist(e) {
		return report, e
	}
	if exists && !apply {
		return report, errors.New("audit reclaim pending; rerun with --apply")
	}
	if err = privatePath(cfg.DataDir, true); err != nil {
		return report, err
	}
	if err = privatePath(filepath.Join(cfg.DataDir, ".lock"), false); err != nil {
		return report, err
	}
	lock, err := platform.Lock(cfg.DataDir)
	if err != nil {
		return report, err
	}
	intent := ""
	if exists {
		intent = auditReclaimIntent
	}
	r, err := openLockedPostingRepository(cfg, lock, func(string) {}, capture, intent)
	if err != nil {
		return report, err
	}
	defer func() {
		err = errors.Join(err, r.Close())
		if err != nil {
			report = AuditReclaimReport{}
		}
	}()
	var plan auditReclaimPlan
	if exists {
		plan, err = resumeAuditReclaimPlan(ctx, r, work)
	} else {
		plan, err = r.buildAuditReclaimPlan(ctx)
	}
	if err != nil {
		return report, err
	}
	report = auditReclaimReport(plan)
	if !apply {
		return report, nil
	}
	if !exists {
		if err = makePrivateDir(work); err != nil {
			return report, err
		}
		checkpoint("audit_reclaim_intent")
		raw, e := encodeAuditReclaim(cfg, plan)
		if e != nil {
			return report, e
		}
		if err = completeActivationFile(filepath.Join(work, "plan.json"), raw); err != nil {
			return report, err
		}
	}
	if err = store.SyncDirectory(work); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(cfg.DataDir); err != nil {
		return report, err
	}
	checkpoint("audit_reclaim_plan")
	if err = r.validateAuditReclaim(ctx, work, plan); err != nil {
		return report, err
	}
	for _, day := range plan.Days {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		if err = removeAuditDay(cfg, work, day, checkpoint); err != nil {
			return report, err
		}
	}
	verified, e := r.VerifyAuditTransfer(ctx)
	if e != nil {
		return report, e
	}
	if !verified.Complete {
		return report, store.ErrCorrupt
	}
	if err = requireEntries(work, []string{"plan.json"}); err != nil {
		return report, err
	}
	if err = os.Remove(filepath.Join(work, "plan.json")); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(work); err != nil {
		return report, err
	}
	checkpoint("audit_reclaim_plan_removed")
	if err = os.Remove(work); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(cfg.DataDir); err != nil {
		return report, err
	}
	report.Applied = true
	return report, nil
}

// resumeAuditReclaimPlan は計画確定前の一致prefixだけを再構成する。移動済みの日があれば推測しない。
func resumeAuditReclaimPlan(ctx context.Context, r *Repository, work string) (auditReclaimPlan, error) {
	names, err := boundedAuditNames(work, 1025)
	if err != nil {
		return auditReclaimPlan{}, err
	}
	path := filepath.Join(work, "plan.json")
	raw, readErr := readPrivate(path, auditReclaimLimit)
	if readErr == nil {
		if p, e := decodeAuditReclaim(r.cfg, raw); e == nil {
			return p, nil
		}
	}
	for _, name := range names {
		if name != "plan.json" {
			return auditReclaimPlan{}, store.ErrCorrupt
		}
	}
	if readErr != nil && !os.IsNotExist(readErr) {
		return auditReclaimPlan{}, readErr
	}
	p, err := r.buildAuditReclaimPlan(ctx)
	if err != nil {
		return p, err
	}
	want, err := encodeAuditReclaim(r.cfg, p)
	if err != nil {
		return p, err
	}
	if err = completeActivationFile(path, want); err != nil {
		return p, err
	}
	return p, nil
}

// removeAuditDay は親を同期してから固定名のfileだけを除去する。欠落分は前回完了と扱う。
func removeAuditDay(cfg Config, work string, day auditReclaimDay, checkpoint func(string)) error {
	source := filepath.Join(cfg.DataDir, "audit", day.Owner.String(), day.Day)
	stage := filepath.Join(work, day.Owner.String()+"_"+day.Day)
	if _, err := os.Lstat(source); err == nil {
		if err = os.Rename(source, stage); err != nil {
			return err
		}
		checkpoint("audit_reclaim_rename")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := store.SyncDirectory(filepath.Dir(source)); err != nil {
		return err
	}
	if err := store.SyncDirectory(work); err != nil {
		return err
	}
	for _, file := range day.Files {
		if err := os.Remove(filepath.Join(stage, file.Name)); err != nil && !os.IsNotExist(err) {
			return err
		}
		checkpoint("audit_reclaim_unlink")
	}
	if _, err := os.Lstat(stage); err == nil {
		if err = store.SyncDirectory(stage); err != nil {
			return err
		}
		if err = os.Remove(stage); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := store.SyncDirectory(work); err != nil {
		return err
	}
	checkpoint("audit_reclaim_day")
	return nil
}
