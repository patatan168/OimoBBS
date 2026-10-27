// 制御snapshotを利用する前に、停止中CLIから保存先の最低reader版と監査を進める。
package bootstrap

import (
	"context"
	"errors"

	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type ControlEnableReport struct {
	MinimumReader uint32 `json:"minimum_reader_version"`
	AuditComplete bool   `json:"audit_complete"`
}

// EnableControlSnapshots は版12を同期保存し、監査移管を追従させる。途中失敗でも版を戻さない。
func (r *Repository) EnableControlSnapshots(ctx context.Context) (ControlEnableReport, error) {
	return r.enableStorageReader(ctx, 12, "control_snapshot_enable")
}

// enableStorageReader は認証管理者のある保存先の最低readerを単調に進める。
func (r *Repository) enableStorageReader(ctx context.Context, version uint32, reason string) (ControlEnableReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return ControlEnableReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return ControlEnableReport{}, err
	}
	admins, err := r.administrators()
	if err != nil {
		return ControlEnableReport{}, err
	}
	if len(admins) == 0 {
		return ControlEnableReport{}, errors.New("an administrator is required before enabling storage formats")
	}
	var site siteState
	if err = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return ControlEnableReport{}, err
	}
	if site.MinimumReader < version {
		site.MinimumReader = version
		if err = appendControl(r.site, reason, []store.Mutation{mutation("site", "state", site, nil)}, []string{}); err != nil {
			r.stopped = true
			return ControlEnableReport{}, err
		}
	}
	budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
	if err = r.catchUpAudit(ctx, &budget); err != nil {
		return ControlEnableReport{}, err
	}
	proof, err := r.requireCandidateProof(ctx)
	if err != nil {
		return ControlEnableReport{}, err
	}
	return ControlEnableReport{site.MinimumReader, proof.Complete}, nil
}
