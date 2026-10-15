// 永続回収計画を現行境界・最新証明と結び、残存日別fileの同一性を確認する。
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

func (r *Repository) validateAuditReclaim(ctx context.Context, work string, p auditReclaimPlan) error {
	if p.Site != siteID(r.site.State()) || len(p.Owners) != len(r.anchors) {
		return store.ErrCorrupt
	}
	proof, err := r.VerifyAuditTransfer(ctx)
	if err != nil {
		return err
	}
	if !proof.Complete {
		return store.ErrCorrupt
	}
	owners := map[domain.ID]auditReclaimOwner{}
	archiveBudget := int64(64 << 20)
	for _, o := range p.Owners {
		if _, ok := owners[o.Anchor.Owner]; ok {
			return store.ErrCorrupt
		}
		if r.anchors[o.Anchor.Owner] != o.Anchor {
			return store.ErrCorrupt
		}
		latest, _, err := r.loadAuditProof(ctx, o.Anchor.Owner, o.Anchor.Kind, &archiveBudget)
		if err != nil {
			return err
		}
		if latest == nil || *latest != o.Proof || o.Proof.Since != o.Anchor.Proof.Since {
			return store.ErrCorrupt
		}
		owners[o.Anchor.Owner] = o
	}
	allowed := map[string]bool{"plan.json": true}
	budget := int64(64 << 20)
	for _, day := range p.Days {
		if err = ctx.Err(); err != nil {
			return err
		}
		owner, ok := owners[day.Owner]
		if !ok || day.Kind != owner.Anchor.Kind {
			return store.ErrCorrupt
		}
		at, err := time.Parse("20060102", day.Day)
		if err != nil {
			return err
		}
		if at.AddDate(0, 0, 1).UnixNano() > int64(owner.Anchor.Proof.Since) || day.Day == time.Unix(0, int64(owner.Proof.Imported)).UTC().Format("20060102") {
			return store.ErrCorrupt
		}
		if len(day.Files) != 2 || day.Files[0].Name != "control.current" || day.Files[1].Name != "control-000001.wal" {
			return store.ErrCorrupt
		}
		name := day.Owner.String() + "_" + day.Day
		if allowed[name] {
			return store.ErrCorrupt
		}
		allowed[name] = true
		source := filepath.Join(r.cfg.DataDir, "audit", day.Owner.String(), day.Day)
		stage := filepath.Join(work, name)
		sourceExists, err := auditPathExists(source)
		if err != nil {
			return err
		}
		stageExists, err := auditPathExists(stage)
		if err != nil {
			return err
		}
		if sourceExists && stageExists {
			return errors.New("audit day exists in both source and work area")
		}
		for _, file := range day.Files {
			if file.Size == 0 || file.Size > 64<<20 || file.SHA == (domain.Hash{}) {
				return store.ErrCorrupt
			}
		}
		if sourceExists {
			if err = validateReclaimFiles(source, day.Files, false, &budget); err != nil {
				return err
			}
		}
		if stageExists {
			if err = validateReclaimFiles(stage, day.Files, true, &budget); err != nil {
				return err
			}
		}
	}
	names, err := boundedAuditNames(work, 1025)
	if err != nil {
		return err
	}
	for _, name := range names {
		if !allowed[name] {
			return store.ErrCorrupt
		}
	}
	return nil
}

func auditPathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// validateReclaimFiles は移動済みの日だけ削除済みfileの欠落を許し、余分な名前や改変を拒否する。
func validateReclaimFiles(dir string, files []auditReclaimFile, partial bool, budget *int64) error {
	names, err := boundedAuditNames(dir, 2)
	if err != nil {
		return err
	}
	if !partial && len(names) != len(files) {
		return store.ErrCorrupt
	}
	expected := map[string]auditReclaimFile{}
	for _, file := range files {
		expected[file.Name] = file
	}
	for _, name := range names {
		file, ok := expected[name]
		if !ok {
			return store.ErrCorrupt
		}
		if uint64(file.Size) > uint64(*budget) {
			return store.ErrHistoryBudget
		}
		raw, err := readPrivate(filepath.Join(dir, name), int64(file.Size))
		if err != nil {
			return err
		}
		*budget -= int64(len(raw))
		if domain.U64(len(raw)) != file.Size || sha256.Sum256(raw) != file.SHA {
			return store.ErrCorrupt
		}
	}
	return nil
}
