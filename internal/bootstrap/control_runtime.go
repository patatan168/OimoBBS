// snapshot世代を通常起動へ接続し、認証済み境界と監査の連続性を必須にする。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func controlOwnerPath(root, kind string, owner domain.ID) string {
	if kind == "site" {
		return filepath.Join(root, "site")
	}
	return filepath.Join(root, "boards", owner.String(), "control")
}

// inspectRuntimeControl は旧配置を維持し、snapshot配置では中断候補を明示的に拒否する。
func inspectRuntimeControl(root, kind string, owner domain.ID) (store.ControlState, error) {
	dir := controlOwnerPath(root, kind, owner)
	m, err := store.InspectControlManifest(dir)
	if err != nil {
		return store.ControlState{}, err
	}
	if m.Snapshot == nil {
		if err = requireEntries(dir, []string{"control.current", "control-000001.wal"}); err != nil {
			return store.ControlState{}, err
		}
		if kind == "site" {
			return store.InspectControl(dir, 1, owner, 0, validateSiteValue)
		}
		return store.InspectControl(dir, 2, owner, 0, validateBoardValue)
	}
	raw, err := readPrivate(filepath.Join(root, "instance.json"), 4096)
	if err != nil {
		return store.ControlState{}, err
	}
	var marker instance
	if err = strictjson.Decode(raw, &marker); err != nil {
		return store.ControlState{}, err
	}
	if marker.Schema != storageFormatVersion {
		return store.ControlState{}, store.ErrCorrupt
	}
	key, err := controlAnchorKey(root)
	if err != nil {
		return store.ControlState{}, err
	}
	defer clear(key[:])
	generation, err := inspectControlGeneration(dir, kind, owner, marker.SiteID, key)
	if err != nil {
		return store.ControlState{}, err
	}
	if len(generation.Pending) != 0 {
		return store.ControlState{}, errors.New("control generation has pending files; offline recovery required")
	}
	return generation.State, nil
}

// loadControlAnchors はHTTP受付前にsnapshotの境界と保持対象の監査正本を照合する。
func (r *Repository) loadControlAnchors() error {
	r.anchors = map[domain.ID]candidateOwner{}
	key, err := controlAnchorKey(r.cfg.DataDir)
	if err != nil {
		return err
	}
	defer clear(key[:])
	site := siteID(r.site.State())
	archiveBudget := int64(64 << 20)
	load := func(kind string, log *store.ControlLog) error {
		h := log.HistoryHeader()
		if h.BaseSeq == 0 {
			return nil
		}
		path := filepath.Join(controlOwnerPath(r.cfg.DataDir, kind, h.Owner), fmt.Sprintf("control-%06d.anchor.json", h.Generation))
		a, err := readControlAnchor(path, site, domain.ID{}, key)
		if err != nil {
			return err
		}
		r.anchors[h.Owner] = a.Owner
		proof, entries, err := r.loadAuditProof(context.Background(), h.Owner, kind, &archiveBudget)
		if err != nil {
			return err
		}
		if proof == nil {
			return store.ErrCorrupt
		}
		verification, report, err := verifyStartupSnapshotAuditState(context.Background(), log, a.Owner, *proof, entries, store.HistoryBudget{Bytes: 64 << 20, Frames: 200000})
		if err != nil {
			return err
		}
		if uint64(report.VerifiedSeq) < h.BaseSeq {
			return errors.New("snapshot audit boundary is not preserved")
		}
		if r.auditVerified == nil {
			r.auditVerified = map[domain.ID]*snapshotAuditVerification{}
		}
		r.auditVerified[h.Owner] = verification
		return nil
	}
	if err = load("site", r.site); err != nil {
		return err
	}
	for _, log := range r.boards {
		if err = load("board", log); err != nil {
			return err
		}
	}
	return nil
}

// verifyStartupSnapshotAudit は検証位置を維持して分割走査し、全証明を照合してから起動を許可する。
// 進捗のない上限超過や破損・取消は返し、検査の省略や無限の再試行は行わない。
func verifyStartupSnapshotAudit(ctx context.Context, log *store.ControlLog, anchor candidateOwner, proof auditTransfer, entries map[domain.ID]auditStoredEntry, limit store.HistoryBudget) (AuditTransferOwner, error) {
	_, report, err := verifyStartupSnapshotAuditState(ctx, log, anchor, proof, entries, limit)
	return report, err
}

// verifyStartupSnapshotAuditState は検証済みのcursorと要約を返し、最初の監査取得での再走査を省く。
func verifyStartupSnapshotAuditState(ctx context.Context, log *store.ControlLog, anchor candidateOwner, proof auditTransfer, entries map[domain.ID]auditStoredEntry, limit store.HistoryBudget) (*snapshotAuditVerification, AuditTransferOwner, error) {
	verification, err := newSnapshotAuditVerification(ctx, log, anchor, proof, entries)
	if err != nil {
		return nil, AuditTransferOwner{}, err
	}
	for {
		before := verification.calculated.Sequence
		budget := limit
		report, err := verification.advance(ctx, log, &budget)
		if err == nil || !onlyAuditHistoryBudget(err) || verification.calculated.Sequence <= before {
			return verification, report, err
		}
	}
}
