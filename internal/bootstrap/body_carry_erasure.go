// 板へ先行登録した満了署名を元正本へ固定し、短命行を有界削除する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const bodyCarryErasureReader = 59

// validateCarryErasure は新しい署名を作らず、固定満了証跡の完全型だけを検査する。
func validateCarryErasure(key string, old, next json.RawMessage) error {
	var v app.BodyCarryRetirement
	if key != "carry_retirement" || len(old) != 0 || strictjson.Decode(next, &v) != nil || v.At <= 0 {
		return store.ErrCorrupt
	}
	return v.ValidateFormat(app.BodyReclamation{})
}

// readErasedBodyCarry は元sealへ固定した満了証跡と、削除途中の残存行の型を照合する。
// 残存行は満了済みの回収対象であり、索引・証拠・受理枠として返さない。
func readErasedBodyCarry(state store.ControlState, proof app.BodyReclamation) (*app.BodyCarry, error) {
	row := state.Rows["reclamation:carry_retirement"]
	var v app.BodyCarryRetirement
	if validateCarryErasure("carry_retirement", nil, row.Value) != nil || strictjson.Decode(row.Value, &v) != nil || v.ValidateFormat(proof) != nil || v.Proof != reclamationDigest(proof) || row.Expires != nil {
		return nil, store.ErrCorrupt
	}
	var seal bodyCarrySeal
	if e := readErasureSeal(state, v, &seal); e != nil {
		return nil, e
	}
	if e := inspectErasedCarryResidue(state, seal); e != nil {
		return nil, e
	}
	return &app.BodyCarry{Retirement: &v}, nil
}

// readErasureSeal は削除後も元sealの件数と元証明hashを保持する。
func readErasureSeal(state store.ControlState, v app.BodyCarryRetirement, seal *bodyCarrySeal) error {
	if strictjson.Decode(state.Rows["reclamation:carry"].Value, seal) != nil || seal.Schema != 1 || seal.Proof != v.Proof || seal.Dedups != v.Dedups || seal.Rates != v.Rates {
		return store.ErrCorrupt
	}
	return nil
}

// inspectErasedCarryResidue は未知型/期限付き行と元件数を超えた残存集合を拒否する。
func inspectErasedCarryResidue(state store.ControlState, seal bodyCarrySeal) error {
	counts := map[string]uint32{}
	for name, row := range state.Rows {
		collection, key, _ := strings.Cut(name, ":")
		if collection != "dedup_carry" && collection != "rate_carry" {
			continue
		}
		if row.Expires != nil || validateBodyCarry(collection, key, nil, row.Value) != nil {
			return store.ErrCorrupt
		}
		counts[collection]++
	}
	if counts["dedup_carry"] > seal.Dedups || counts["rate_carry"] > seal.Rates {
		return store.ErrCorrupt
	}
	return nil
}

// inspectCarryErasureReference は元への署名コピーだけを信頼せず、板の先行正本との一致を要求する。
func inspectCarryErasureReference(reader uint32, board, state store.ControlState, owner domain.ID, key uint64) error {
	row, found := state.Rows["reclamation:carry_retirement"]
	if !found {
		return nil
	}
	if reader < bodyCarryErasureReader {
		return store.ErrCorrupt
	}
	v, e := decodeBodyCarryRetirementAnchor(fmt.Sprint(key), board.Rows["carry_retirement:"+fmt.Sprint(key)].Value)
	if e != nil || v.Proof.Owner != owner {
		return store.ErrCorrupt
	}
	var copied app.BodyCarryRetirement
	if strictjson.Decode(row.Value, &copied) != nil || copied != v.Retirement {
		return store.ErrCorrupt
	}
	return nil
}

// ReclaimExpiredBodyCarry は署名先行登録後、最大128行を削除する。旧WALは別工程で回収する。
func (r *Repository) ReclaimExpiredBodyCarry(ctx context.Context, owner domain.ID, key uint64, limit int) (int, error) {
	if limit < 1 || limit > 128 {
		return 0, errors.New("carry row limit must be 1..128")
	}
	if e := r.RegisterExpiredBodyCarry(ctx, owner, key); e != nil {
		return 0, e
	}
	if _, e := r.enableStorageReader(ctx, bodyCarryErasureReader, "body_carry_erasure_enable"); e != nil {
		return 0, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return 0, e
	}
	b := r.posting[owner]
	if b == nil {
		return 0, store.ErrIncomplete
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		v, e := b.prepareCarryRetirement(ctx, key)
		if e != nil {
			return 0, e
		}
		return b.eraseStoredBodyCarry(v, limit)
	})
	if value == nil {
		return 0, e
	}
	return value.(int), e
}

// eraseStoredBodyCarry は元の全集合照合を終えてから同じ署名を保存し、行を削除する。
func (b *postingBoard) eraseStoredBodyCarry(v bodyCarryRetirementAnchor, limit int) (int, error) {
	log := b.deletions[uint64(v.Proof.Key)]
	if _, found := log.State().Rows["reclamation:carry_retirement"]; !found {
		carry, e := readBodyCarry(log.State(), v.Proof)
		if e != nil || carry == nil {
			return 0, store.ErrCorrupt
		}
		if e = v.Retirement.VerifySource(v.Proof, *carry, domain.Time(b.clock().UnixNano()), b.key.Public().(ed25519.PublicKey)); e != nil {
			return 0, e
		}
		if e = appendControl(log, "body_carry_erasure", []store.Mutation{mutation("reclamation", "carry_retirement", v.Retirement, nil)}, []string{v.Proof.Deletion.String()}); e != nil {
			b.stopped = true
			return 0, e
		}
		if e = b.afterDeletion("carry_erasure:source"); e != nil {
			return 0, e
		}
	}
	return b.eraseCarryPage(v.Proof, limit)
}

// eraseCarryPage は先行署名と板正本を再検査し、一frameの削除をSyncする。
func (b *postingBoard) eraseCarryPage(proof app.BodyReclamation, limit int) (int, error) {
	log := b.deletions[uint64(proof.Key)]
	if _, e := b.boundBodyCarry(log.State(), proof); e != nil {
		return 0, e
	}
	names := []string{}
	for name := range log.State().Rows {
		if strings.HasPrefix(name, "dedup_carry:") || strings.HasPrefix(name, "rate_carry:") {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	changes := make([]store.Mutation, 0, min(limit, len(names)))
	for _, name := range names[:min(limit, len(names))] {
		collection, key, _ := strings.Cut(name, ":")
		changes = append(changes, mutation(collection, key, nil, nil))
	}
	if len(changes) == 0 {
		return 0, nil
	}
	if e := appendControl(log, "body_carry_erasure_page", changes, []string{proof.Deletion.String()}); e != nil {
		b.stopped = true
		return 0, e
	}
	return len(changes), b.afterDeletion("carry_erasure:rows")
}
