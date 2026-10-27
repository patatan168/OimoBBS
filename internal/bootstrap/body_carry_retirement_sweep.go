// 起動/毎分の既存保守から、完成済み本体のcarry満了を一件ずつ固定する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// sweepBodyCarryRetirementsLocked は混雑板の探索を延期し、最大一件の登録/行削除/旧WAL回収を進める。
func (r *Repository) sweepBodyCarryRetirementsLocked(ctx context.Context) error {
	ids := make([]domain.ID, 0, len(r.posting))
	for id := range r.posting {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return slices.Compare(a[:], b[:]) })
	for _, id := range ids {
		b := r.posting[id]
		value, e := b.worker.SubmitIdle(ctx, func() (any, error) { return b.nextExpiredBodyCarry(ctx) })
		if errors.Is(e, board.ErrBusy) {
			continue
		}
		if e != nil {
			return e
		}
		v := value.(*bodyCarryRetirementAnchor)
		if v == nil {
			continue
		}
		return r.saveSweptCarryRetirement(ctx, b, uint64(v.Proof.Key))
	}
	return nil
}

// saveSweptCarryRetirement は保存容量を確保し、readerの先行Sync後に元を再検査する。
func (r *Repository) saveSweptCarryRetirement(ctx context.Context, b *postingBoard, key uint64) error {
	release, e := r.reservePrivateLossBytes(1 << 20)
	if e != nil {
		return e
	}
	defer release()
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = r.enableCarryRetirementReaderLocked(); e != nil {
		return e
	}
	_, e = b.worker.Submit(ctx, func() (any, error) {
		v, e := b.prepareCarryRetirement(ctx, key)
		if e != nil {
			return nil, e
		}
		if e = b.persistCarryRetirement(v); e != nil {
			return nil, e
		}
		return nil, nil
	})
	if e != nil {
		return e
	}
	return r.reclaimSweptCarryLocked(ctx, b, key)
}

// nextExpiredBodyCarry は未完成本体を保留し、既存証跡の時計下限を維持する。
func (b *postingBoard) nextExpiredBodyCarry(ctx context.Context) (*bodyCarryRetirementAnchor, error) {
	if b.stopped {
		return nil, ErrPostingUnavailable
	}
	if !b.carryEnabled {
		return nil, nil
	}
	if e := b.checkCarryRetirementClock(); e != nil {
		return nil, e
	}
	keys := make([]uint64, 0, len(b.deletions))
	for key := range b.deletions {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		v, e := b.expiredCarryCandidate(ctx, key)
		if e != nil || v != nil {
			return v, e
		}
	}
	return nil, nil
}

// checkCarryRetirementClock は候補の選択より先に、板全体の既存満了時刻を照合する。
func (b *postingBoard) checkCarryRetirementClock() error {
	now := domain.Time(b.clock().UnixNano())
	for name, row := range b.control.State().Rows {
		key, found := strings.CutPrefix(name, "carry_retirement:")
		if !found {
			continue
		}
		v, e := decodeBodyCarryRetirementAnchor(key, row.Value)
		if e != nil {
			return e
		}
		if e = v.Retirement.Verify(v.Proof, now, b.key.Public().(ed25519.PublicKey)); e != nil {
			return e
		}
	}
	return nil
}

// expiredCarryCandidate は未満了を正常な保留とし、欠落や改変を保留扱いにしない。
func (b *postingBoard) expiredCarryCandidate(ctx context.Context, key uint64) (*bodyCarryRetirementAnchor, error) {
	if _, ok := b.control.State().Rows["carry_retirement:"+fmt.Sprint(key)]; ok {
		return b.pendingCarryCleanup(ctx, key)
	}
	state := b.deletions[key].State()
	proof, e := readBodyReclamation(state, b.owner, key, b.key.Public().(ed25519.PublicKey))
	if e != nil || proof == nil {
		return nil, e
	}
	// 満了未登録の元body時計下限前は、既存索引を保持して回収を保留する。
	if domain.Time(b.clock().UnixNano()) < max(proof.At, proof.Floor) {
		return nil, nil
	}
	task, e := bodyTask(state, proof.Deletion)
	if e != nil || task.State != "complete" {
		return nil, e
	}
	v, e := b.prepareCarryRetirement(ctx, key)
	if errors.Is(e, app.ErrBodyCarryNotExpired) {
		return nil, nil
	}
	return &v, e
}

// enableCarryRetirementReaderLocked は新しい板署名より先に最低reader58をSyncする。
func (r *Repository) enableCarryRetirementReaderLocked() error {
	return r.enableCarryStorageReaderLocked(bodyCarryRetirementReader, "body_carry_retirement_enable")
}

// enableCarryStorageReaderLocked は既存site行へ必要なreaderを先行Syncする。
func (r *Repository) enableCarryStorageReaderLocked(reader uint32, reason string) error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if site.MinimumReader >= reader {
		return nil
	}
	site.MinimumReader = reader
	e := appendControl(r.site, reason, []store.Mutation{mutation("site", "state", site, nil)}, []string{})
	if e != nil {
		r.stopped = true
	}
	return e
}

// pendingCarryCleanup は登録済みの未回収元を選び、回収済みdirectoryも同期する。
func (b *postingBoard) pendingCarryCleanup(ctx context.Context, key uint64) (*bodyCarryRetirementAnchor, error) {
	dir := filepath.Join(b.root, "expiry", b.owner.String(), fmt.Sprint(key))
	m, e := inspectDeletionLayout(dir, b.owner, key)
	if e != nil {
		return nil, e
	}
	if m.Snapshot != nil {
		if _, e = os.Lstat(filepath.Join(dir, "control-000001.wal")); os.IsNotExist(e) {
			if e = ctx.Err(); e != nil {
				return nil, e
			}
			return nil, store.SyncDirectory(dir)
		} else if e != nil {
			return nil, e
		}
	}
	v, e := b.prepareCarryRetirement(ctx, key)
	return &v, e
}

// reclaimSweptCarryLocked は一回128行を削除し、空になった元だけ初回圧縮する。
func (r *Repository) reclaimSweptCarryLocked(ctx context.Context, b *postingBoard, key uint64) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := r.enableCarryStorageReaderLocked(bodyCarryErasureReader, "body_carry_erasure_enable"); e != nil {
		return e
	}
	_, e := b.worker.Submit(ctx, func() (any, error) {
		v, e := b.prepareCarryRetirement(ctx, key)
		if e != nil {
			return nil, e
		}
		_, e = b.eraseStoredBodyCarry(v, 128)
		return nil, e
	})
	if e != nil {
		return e
	}
	return r.compactSweptCarryLocked(ctx, b, key)
}

// compactSweptCarryLocked は空の元の候補容量を予約し、reader60確定後に物理回収する。
func (r *Repository) compactSweptCarryLocked(ctx context.Context, b *postingBoard, key uint64) error {
	value, e := b.worker.Submit(ctx, func() (any, error) {
		log := b.deletions[key]
		if carryRowsInState(log.State()) != 0 {
			return 0, nil
		}
		dir := filepath.Join(b.root, "expiry", b.owner.String(), fmt.Sprint(key))
		m, e := inspectDeletionLayout(dir, b.owner, key)
		if e != nil {
			return 0, e
		}
		plan, e := prepareCarrySnapshotPlan(dir, m, log.State())
		return len(plan.snapshot) + len(plan.delta) + len(plan.current), e
	})
	if e != nil {
		return e
	}
	size := value.(int)
	if size == 0 {
		return nil
	}
	release, e := r.reservePrivateLossBytes(uint64(size))
	if e != nil {
		return e
	}
	defer release()
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = r.enableCarryStorageReaderLocked(bodyCarrySnapshotReader, "body_carry_snapshot_enable"); e != nil {
		return e
	}
	_, e = b.worker.Submit(ctx, func() (any, error) { return nil, b.compactCarrySource(ctx, key) })
	return e
}
