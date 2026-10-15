// 停止中に保持下限の境界・最新証明を更新し、永続intentから同じ候補で再開する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/platform"
	"oimobbs/internal/store"
)

// ApplyAuditRetention は全所有者の更新とRepository復旧の完了後だけ通常起動を再許可する。
// 途中失敗ではintentを残す。日別監査は削除せず、同じ候補を再実行して完了させる。
func ApplyAuditRetention(ctx context.Context, cfg Config, input string, capture func([]byte) error) (AuditRetentionReport, error) {
	return applyAuditRetention(ctx, cfg, input, capture, func(string) {})
}

func applyAuditRetention(ctx context.Context, cfg Config, input string, capture func([]byte) error, checkpoint func(string)) (report AuditRetentionReport, err error) {
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
	m, err := readRetentionCandidate(cfg, input)
	if err != nil {
		return report, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return report, err
	}
	name := fmt.Sprintf(".audit-retention-%s-%x", m.ID, sha256.Sum256(payload))
	intent := filepath.Join(cfg.DataDir, name)
	if _, e := os.Lstat(intent); os.IsNotExist(e) {
		r, e := OpenPostingRepository(cfg, capture)
		if e != nil {
			return report, e
		}
		complete, e := retentionAlreadyApplied(ctx, r, m)
		if e != nil || complete {
			if complete {
				report = retentionReport(m)
				report.Applied = true
			}
			return report, errors.Join(e, r.Close())
		}
		_, e = r.VerifyAuditRetention(ctx, input)
		if e == nil {
			e = makePrivateDir(intent)
		}
		if e == nil {
			checkpoint("retention_intent")
		}
		e = errors.Join(e, r.Close())
		if e != nil {
			return report, e
		}
	} else if e != nil {
		return report, e
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
	owned := true
	defer func() {
		if owned {
			err = errors.Join(err, platform.Unlock(lock))
		}
		if err != nil {
			report = AuditRetentionReport{}
		}
	}()
	roots := append([]string{".lock", "instance.json", "keys", "site", name}, emptyDirectories...)
	if err = requireEntries(cfg.DataDir, roots); err != nil {
		return report, err
	}
	if err = validateRetentionIntent(intent, m); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(cfg.DataDir); err != nil {
		return report, err
	}
	// auditの追記途中だけを通常のWAL復旧で確定し、全所有者を再照合する。
	for _, o := range m.Owners {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		sink := auditSink{root: filepath.Join(cfg.DataDir, "audit")}
		e := sink.open(o.Before.Owner, o.Before.Kind, time.Unix(0, int64(m.Created)).UTC().Format("20060102"))
		if err = errors.Join(e, sink.close()); err != nil {
			return report, err
		}
	}
	checked, e := checkLockedPostingIntent(cfg, true, true, name)
	if e != nil {
		return report, e
	}
	if checked.SiteID != m.Site || checked.BoardCount+1 != len(m.Owners) {
		return report, store.ErrCorrupt
	}
	items, err := validateRetentionApply(ctx, cfg, m)
	if err != nil {
		return report, err
	}
	for _, item := range items {
		if err = checkActivationPrefix(filepath.Join(intent, item.owner.Before.Owner.String()+".anchor"), item.anchor); err != nil {
			return report, err
		}
	}
	for _, item := range items {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		if err = installRetentionOwner(cfg, intent, item, checkpoint); err != nil {
			return report, err
		}
		checkpoint("retention_owner")
	}
	if err = requireEmpty(intent); err != nil {
		return report, err
	}
	owned = false
	r, err := openLockedPostingRepository(cfg, lock, func(string) {}, capture, name)
	if err != nil {
		return report, err
	}
	checkpoint("retention_validated")
	err = os.Remove(intent)
	if err == nil {
		err = store.SyncDirectory(cfg.DataDir)
	}
	err = errors.Join(err, r.Close())
	if err != nil {
		return report, err
	}
	report = retentionReport(m)
	report.Applied = true
	return report, nil
}

// validateRetentionIntent は候補にある所有者の一時境界だけを許可し、未知ファイルを残したまま進めない。
func validateRetentionIntent(dir string, m retentionCandidate) error {
	if err := privatePath(dir, true); err != nil {
		return err
	}
	names, err := activationNames(dir)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, o := range m.Owners {
		allowed[o.Before.Owner.String()+".anchor"] = true
	}
	for _, name := range names {
		if !allowed[name] {
			return store.ErrCorrupt
		}
		if err = privatePath(filepath.Join(dir, name), false); err != nil {
			return err
		}
	}
	return nil
}

// retentionAlreadyApplied は完了後かつ元状態が進んでいない同一候補の再実行を受け付ける。
func retentionAlreadyApplied(ctx context.Context, r *Repository, m retentionCandidate) (bool, error) {
	if len(r.anchors) != len(m.Owners) {
		return false, nil
	}
	for _, o := range m.Owners {
		if r.anchors[o.After.Owner] != o.After {
			return false, nil
		}
	}
	// 物理回収後は旧Sinceのprefixを要求しない。認証済みの更新後境界と現行証明だけを照合する。
	report, err := r.VerifyAuditTransfer(ctx)
	if err != nil {
		return false, err
	}
	if !report.Complete {
		return false, store.ErrCorrupt
	}
	if siteID(r.site.State()) != m.Site {
		return false, store.ErrCorrupt
	}
	budget := int64(64 << 20)
	for _, o := range m.Owners {
		proof, _, err := r.loadAuditProof(ctx, o.After.Owner, o.After.Kind, &budget)
		if err != nil {
			return false, err
		}
		if proof == nil || *proof != o.AfterProof {
			return false, store.ErrCorrupt
		}
	}
	return true, nil
}
