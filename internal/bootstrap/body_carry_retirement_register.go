// carry満了証跡を既存板正本へ先行Syncし、稼働中と再起動後の短命索引を閉じる。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// RegisterExpiredBodyCarry は指定スレッドの全carry満了を固定する。
// 未満了/不完全な元では保存を変更しない。原本行と旧世代の物理削除は別工程。
func (r *Repository) RegisterExpiredBodyCarry(ctx context.Context, owner domain.ID, key uint64) error {
	if e := r.registerBodyCarryRetirement(ctx, owner, key, false); e != nil {
		return e
	}
	if _, e := r.enableStorageReader(ctx, bodyCarryRetirementReader, "body_carry_retirement_enable"); e != nil {
		return e
	}
	return r.registerBodyCarryRetirement(ctx, owner, key, true)
}

// registerBodyCarryRetirement はreader更新前後に同じ元を所有者列内で再検査する。
func (r *Repository) registerBodyCarryRetirement(ctx context.Context, owner domain.ID, key uint64, commit bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	b := r.posting[owner]
	if b == nil {
		return store.ErrIncomplete
	}
	_, e := b.worker.Submit(ctx, func() (any, error) {
		v, e := b.prepareCarryRetirement(ctx, key)
		if e != nil || !commit {
			return nil, e
		}
		return nil, b.persistCarryRetirement(v)
	})
	return e
}

// prepareCarryRetirement は完成task、物理本体消去、保存済み全集合を先に照合する。
func (b *postingBoard) prepareCarryRetirement(ctx context.Context, key uint64) (bodyCarryRetirementAnchor, error) {
	var v bodyCarryRetirementAnchor
	p, log := b.threads[key], b.deletions[key]
	if b.stopped || !b.carryEnabled || p == nil || log == nil {
		return v, store.ErrIncomplete
	}
	state, e := b.requiredReclaimPhysicalState(key, log)
	if e != nil {
		return v, e
	}
	proof, e := b.completedCarryBody(state, key)
	if e != nil {
		return v, e
	}
	if e = p.CheckRequiredOriginalReclamation(ctx, domain.Time(b.clock().UnixNano()), b.key.Public().(ed25519.PublicKey)); e != nil {
		return v, e
	}
	return b.carryRetirementCertificate(state, *proof)
}

// completedCarryBody は署名済み元bodyと完成taskの組を要求する。
func (b *postingBoard) completedCarryBody(state store.ControlState, key uint64) (*app.BodyReclamation, error) {
	proof, e := readBodyReclamation(state, b.owner, key, b.key.Public().(ed25519.PublicKey))
	if e != nil || proof == nil {
		return nil, store.ErrCorrupt
	}
	task, e := bodyTask(state, proof.Deletion)
	if e != nil || task.State != "complete" {
		return nil, store.ErrIncomplete
	}
	return proof, nil
}

// carryRetirementCertificate は再送時の固定署名を維持し、初回だけ元集合から署名する。
func (b *postingBoard) carryRetirementCertificate(state store.ControlState, proof app.BodyReclamation) (bodyCarryRetirementAnchor, error) {
	v := bodyCarryRetirementAnchor{Proof: proof}
	carry, e := readBodyCarry(state, proof)
	if e != nil || carry == nil {
		return v, store.ErrCorrupt
	}
	now := domain.Time(b.clock().UnixNano())
	if row, ok := b.control.State().Rows["carry_retirement:"+fmt.Sprint(proof.Key)]; ok {
		v, e = decodeBodyCarryRetirementAnchor(fmt.Sprint(proof.Key), row.Value)
		if e != nil {
			return v, e
		}
		return v, verifyBoundCarryRetirement(v.Retirement, proof, *carry, now, b.key.Public().(ed25519.PublicKey))
	}
	v.Retirement, e = app.PrepareBodyCarryRetirement(proof, *carry, now, b.key)
	return v, e
}

// persistCarryRetirement は耐久署名確定後だけ所有者へ空の索引を渡す。
func (b *postingBoard) persistCarryRetirement(v bodyCarryRetirementAnchor) error {
	key := fmt.Sprint(v.Proof.Key)
	if _, ok := b.control.State().Rows["carry_retirement:"+key]; !ok {
		if e := appendControl(b.control, "body_carry_retirement", []store.Mutation{mutation("carry_retirement", key, v, nil)}, []string{v.Proof.Deletion.String()}); e != nil {
			b.stopped = true
			return e
		}
	}
	e := b.threads[uint64(v.Proof.Key)].RestoreBodyCarry(app.BodyCarry{Retirement: &v.Retirement}, domain.Time(b.clock().UnixNano()), b.key.Public().(ed25519.PublicKey))
	if e != nil {
		b.stopped = true
	}
	return e
}

// boundBodyCarry は元の全件照合を維持し、正本の満了証跡がある場合だけ索引を閉じる。
func (b *postingBoard) boundBodyCarry(state store.ControlState, proof app.BodyReclamation) (*app.BodyCarry, error) {
	carry, e := readBodyCarry(state, proof)
	if e != nil || carry == nil {
		return carry, e
	}
	row, ok := b.control.State().Rows["carry_retirement:"+fmt.Sprint(proof.Key)]
	if !ok {
		if carry.Retirement != nil {
			return nil, store.ErrCorrupt
		}
		return carry, nil
	}
	v, e := decodeBodyCarryRetirementAnchor(fmt.Sprint(proof.Key), row.Value)
	if e != nil {
		return nil, e
	}
	if e = verifyBoundCarryRetirement(v.Retirement, proof, *carry, domain.Time(b.clock().UnixNano()), b.key.Public().(ed25519.PublicKey)); e != nil {
		return nil, e
	}
	return &app.BodyCarry{Retirement: &v.Retirement}, nil
}

// verifyBoundCarryRetirement は初回の全集合照合と、削除開始後の同一署名照合を区別する。
func verifyBoundCarryRetirement(v app.BodyCarryRetirement, proof app.BodyReclamation, carry app.BodyCarry, now domain.Time, public ed25519.PublicKey) error {
	if carry.Retirement == nil {
		return v.VerifySource(proof, carry, now, public)
	}
	if v != *carry.Retirement {
		return store.ErrCorrupt
	}
	return v.Verify(proof, now, public)
}
