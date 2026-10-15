// 短命索引を有界frameへ保存し、署名済み集合の完成を確認してから公開本体を回収する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"sort"
	"strings"
)

type bodyCarrySeal struct {
	Schema uint32      `json:"schema"`
	Proof  domain.Hash `json:"proof_sha256"`
	Dedups uint32      `json:"dedup_count"`
	Rates  uint32      `json:"rate_count"`
}

func validateBodyCarry(collection, key string, old, next json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(next), []byte("null")) && len(old) != 0 && (collection == "dedup_carry" || collection == "rate_carry") {
		return validateBodyCarry(collection, key, nil, old)
	}
	if len(old) != 0 {
		return store.ErrCorrupt
	}
	switch collection {
	case "reclamation":
		var v bodyCarrySeal
		if key != "carry" || strictjson.Decode(next, &v) != nil || v.Schema != 1 || v.Proof == (domain.Hash{}) || v.Dedups > store.MaxPackEntries || v.Rates > store.MaxPackEntries {
			return store.ErrCorrupt
		}
	case "dedup_carry":
		var v app.DedupCarry
		if strictjson.Decode(next, &v) != nil || key != v.ID.String() {
			return store.ErrCorrupt
		}
		if _, e := v.Validate(0); e != nil {
			return e
		}
	case "rate_carry":
		var v app.RateCarry
		if strictjson.Decode(next, &v) != nil || key != v.ID.String() {
			return store.ErrCorrupt
		}
		return v.Validate()
	default:
		return store.ErrCorrupt
	}
	return nil
}

// readBodyCarry は本文に触れず、独立保存された行を署名済み集合のdigestへ照合する。
// sealのない途中保存は完成扱いにせず、元証拠から同じ集合を再開する。
func readBodyCarry(state store.ControlState, proof app.BodyReclamation) (*app.BodyCarry, error) {
	if _, found := state.Rows["reclamation:carry_retirement"]; found {
		return readErasedBodyCarry(state, proof)
	}
	row, ok := state.Rows["reclamation:carry"]
	if !ok {
		return nil, nil
	}
	var seal bodyCarrySeal
	if validateBodyCarry("reclamation", "carry", nil, row.Value) != nil || strictjson.Decode(row.Value, &seal) != nil || seal.Proof != reclamationDigest(proof) {
		return nil, store.ErrCorrupt
	}
	out := app.BodyCarry{Dedups: []app.DedupCarry{}, Rates: []app.RateCarry{}}
	for name, row := range state.Rows {
		switch {
		case strings.HasPrefix(name, "dedup_carry:"):
			var v app.DedupCarry
			if strictjson.Decode(row.Value, &v) != nil {
				return nil, store.ErrCorrupt
			}
			out.Dedups = append(out.Dedups, v)
		case strings.HasPrefix(name, "rate_carry:"):
			var v app.RateCarry
			if strictjson.Decode(row.Value, &v) != nil {
				return nil, store.ErrCorrupt
			}
			out.Rates = append(out.Rates, v)
		}
	}
	if len(out.Dedups) > store.MaxPackEntries || len(out.Rates) > store.MaxPackEntries {
		return nil, store.ErrCorrupt
	}
	if len(out.Dedups) != int(seal.Dedups) || len(out.Rates) != int(seal.Rates) {
		return nil, store.ErrCorrupt
	}
	sort.Slice(out.Dedups, func(i, j int) bool { return out.Dedups[i].Source < out.Dedups[j].Source })
	sort.Slice(out.Rates, func(i, j int) bool { return out.Rates[i].Number < out.Rates[j].Number })
	d, r, e := out.Digest(proof.Floor)
	if e != nil || d != proof.DedupSHA || r != proof.RateSHA {
		return nil, errors.Join(store.ErrCorrupt, e)
	}
	return &out, nil
}

// saveBodyCarry は途中まで確定した行を検算し、最大128行ずつSyncする。
// 各frameは1MiB内。sealの先行Syncを終えるまで本体unlinkを開始しない。
func (b *postingBoard) saveBodyCarry(proof app.BodyReclamation) error {
	log := b.deletions[uint64(proof.Key)]
	state := log.State()
	if carry, e := readBodyCarry(state, proof); e != nil || carry != nil {
		return e
	}
	carry, e := b.threads[uint64(proof.Key)].ExportBodyCarry(proof.Floor, proof.CarryAt())
	if e != nil {
		return e
	}
	return b.persistBodyCarry(proof, carry)
}

// persistBodyCarry は固定した集合を耐久保存し、途中保存の余分な行や改変を拒否する。
func (b *postingBoard) persistBodyCarry(proof app.BodyReclamation, carry app.BodyCarry) error {
	log := b.deletions[uint64(proof.Key)]
	state := log.State()
	d, r, e := carry.Digest(proof.Floor)
	if e != nil || d != proof.DedupSHA || r != proof.RateSHA {
		return errors.Join(app.ErrEvidenceGap, e)
	}
	wanted := make(map[string]store.Mutation, len(carry.Dedups)+len(carry.Rates))
	for _, v := range carry.Dedups {
		m := mutation("dedup_carry", v.ID.String(), v, nil)
		wanted[m.Collection+":"+m.Key] = m
	}
	for _, v := range carry.Rates {
		m := mutation("rate_carry", v.ID.String(), v, nil)
		wanted[m.Collection+":"+m.Key] = m
	}
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "dedup_carry:") && !strings.HasPrefix(name, "rate_carry:") {
			continue
		}
		m, ok := wanted[name]
		if !ok || !bytes.Equal(row.Value, m.Value) {
			return store.ErrCorrupt
		}
		delete(wanted, name)
	}
	names := make([]string, 0, len(wanted))
	for name := range wanted {
		names = append(names, name)
	}
	sort.Strings(names)
	for first := 0; first < len(names); first += 128 {
		changes := make([]store.Mutation, 0, 128)
		for _, name := range names[first:min(first+128, len(names))] {
			changes = append(changes, wanted[name])
		}
		if e = appendControl(log, "thread_body_carry", changes, []string{proof.Deletion.String()}); e != nil {
			return e
		}
		if e = b.afterDeletion("reclaim:carry_page"); e != nil {
			return e
		}
	}
	seal := bodyCarrySeal{1, reclamationDigest(proof), uint32(len(carry.Dedups)), uint32(len(carry.Rates))}
	if e = appendControl(log, "thread_body_carry_seal", []store.Mutation{mutation("reclamation", "carry", seal, nil)}, []string{proof.Deletion.String()}); e != nil {
		return e
	}
	if _, e = readBodyCarry(log.State(), proof); e != nil {
		return e
	}
	return b.afterDeletion("reclaim:carry_seal")
}
