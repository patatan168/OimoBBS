// 再開時の新旧状態の裁定と、候補に束縛した監査証明・境界の永続化を行う。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type retentionInstall struct {
	owner  retentionOwner
	path   string
	anchor []byte
}

// validateRetentionApply は更新前後の一致状態だけを許可し、全所有者の再証明後に設置情報を返す。
func validateRetentionApply(ctx context.Context, cfg Config, m retentionCandidate) ([]retentionInstall, error) {
	raw, err := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if err != nil {
		return nil, err
	}
	var marker instance
	if err = strictjson.Decode(raw, &marker); err != nil {
		return nil, err
	}
	if marker.Schema != storageFormatVersion || marker.SiteID != m.Site {
		return nil, store.ErrCorrupt
	}
	if err = checkKeys(cfg.DataDir, marker); err != nil {
		return nil, err
	}
	key, err := controlAnchorKey(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	r := Repository{cfg: cfg}
	items := []retentionInstall{}
	seen := map[domain.ID]bool{}
	budget := store.HistoryBudget{Bytes: 128 << 20, Frames: 400000}
	archiveBudget := int64(64 << 20)
	for _, o := range m.Owners {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if seen[o.Before.Owner] {
			return nil, store.ErrCorrupt
		}
		seen[o.Before.Owner] = true
		dir := controlOwnerPath(cfg.DataDir, o.Before.Kind, o.Before.Owner)
		generation, err := inspectControlGeneration(dir, o.Before.Kind, o.Before.Owner, m.Site, key)
		if err != nil {
			return nil, err
		}
		if generation.Anchor == nil || len(generation.Pending) != 0 {
			return nil, store.ErrCorrupt
		}
		actual := *generation.Anchor
		if actual.Owner != o.Before && actual.Owner != o.After {
			return nil, errors.New("retention boundary differs from candidate")
		}
		proof, entries, err := r.loadAuditProof(ctx, o.Before.Owner, o.Before.Kind, &archiveBudget)
		if err != nil {
			return nil, err
		}
		if proof == nil || (*proof != o.BeforeProof && *proof != o.AfterProof) {
			return nil, errors.New("retention proof differs from candidate")
		}
		validate := store.ValueValidator(validateSiteValue)
		if o.Before.Kind == "board" {
			validate = validateBoardValue
		}
		log, err := store.OpenControlWithValidators(dir, o.Before.header().Kind, o.Before.Owner, 0, validate, snapshotValues(o.Before.Kind))
		if err != nil {
			return nil, err
		}
		after, next, e := renewAuditBoundary(ctx, log, o.Before, o.BeforeProof, entries, time.Unix(0, int64(m.Created)), &budget)
		err = errors.Join(e, log.Close())
		if err != nil {
			return nil, err
		}
		if after != o.After || next != o.AfterProof {
			return nil, store.ErrCorrupt
		}
		actual.Owner = o.After
		if err = validateAnchor(actual); err != nil {
			return nil, err
		}
		payload, err := json.Marshal(actual)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(anchorEnvelope{payload, identity.MAC(key[:], "oimo/control-anchor/v1", payload)})
		if err != nil {
			return nil, err
		}
		items = append(items, retentionInstall{o, filepath.Join(dir, fmt.Sprintf("control-%06d.anchor.json", o.Before.Generation)), raw})
	}
	if !seen[m.Site] {
		return nil, store.ErrCorrupt
	}
	return items, nil
}

// installRetentionOwner は新しい最新証明を先に同期し、認証境界をrenameで置換する。
func installRetentionOwner(cfg Config, intent string, item retentionInstall, checkpoint func(string)) error {
	p := item.owner.AfterProof
	sink := auditSink{root: filepath.Join(cfg.DataDir, "audit")}
	err := sink.open(p.Owner, p.OwnerKind, time.Unix(0, int64(p.Imported)).UTC().Format("20060102"))
	if err != nil {
		return errors.Join(err, sink.close())
	}
	same := false
	if row, ok := sink.log.State().Rows["import_receipt:source"]; ok {
		var prior auditTransfer
		err = strictjson.Decode(row.Value, &prior)
		same = prior == p
	}
	if err == nil && !same {
		err = appendControl(sink.log, "audit_retention_update", []store.Mutation{mutation("import_receipt", "source", p, nil)}, []string{})
	}
	if err = errors.Join(err, sink.close()); err != nil {
		return err
	}
	checkpoint("retention_proof")
	temp := filepath.Join(intent, p.Owner.String()+".anchor")
	if err = completeActivationFile(temp, item.anchor); err != nil {
		return err
	}
	if err = store.SyncDirectory(intent); err != nil {
		return err
	}
	checkpoint("retention_anchor_sync")
	if err = os.Rename(temp, item.path); err != nil {
		return err
	}
	checkpoint("retention_anchor_rename")
	if err = store.SyncDirectory(filepath.Dir(item.path)); err != nil {
		return err
	}
	if err = store.SyncDirectory(intent); err != nil {
		return err
	}
	return nil
}
