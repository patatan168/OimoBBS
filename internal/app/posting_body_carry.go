// 回収後の短命索引を、元本文を含まない独立した値へ変換する。
package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// DedupCarry は元の期限と確定位置を保つ、固定長の再送拒否索引。
type DedupCarry struct {
	ID     domain.ID  `json:"id"`
	Source domain.U64 `json:"source_base_seq"`
	Entry  string     `json:"entry_base64"`
}

// RateCarry は本文・元IPなしで受理枠を引き継ぐ。期限は元投稿から61分。
type RateCarry struct {
	ID      domain.ID        `json:"operation_id"`
	Number  uint32           `json:"post_number"`
	At      domain.Time      `json:"committed_at_ns"`
	Expires domain.Time      `json:"expires_at_ns"`
	Keys    []domain.RateKey `json:"rate_keys"`
}

// Validate は元期限・固定CRC・canonical Base64を検査する。
func (v DedupCarry) Validate(floor domain.Time) (store.PackDedup, error) {
	raw, e := base64.StdEncoding.Strict().DecodeString(v.Entry)
	if e != nil || base64.StdEncoding.EncodeToString(raw) != v.Entry {
		return store.PackDedup{}, store.ErrCorrupt
	}
	d, e := store.DecodeRejectedDedup(raw, v.Source, floor)
	if e != nil || d.ID != v.ID || d.Seq != v.Source {
		return store.PackDedup{}, store.ErrCorrupt
	}
	return d, nil
}

// Validate は有界な規制キー集合と元投稿に固定された期限を検査する。
func (v RateCarry) Validate() error {
	if v.ID == (domain.ID{}) || v.Number == 0 || v.At <= 0 || v.At > domain.Time(math.MaxInt64)-3660e9 || v.Expires != v.At+3660e9 || v.Keys == nil || len(v.Keys) > 16 {
		return store.ErrCorrupt
	}
	prior := ""
	for _, k := range v.Keys {
		if k.Rule == (domain.ID{}) || k.KeyID == 0 || k.Cost == 0 || k.Rule.String() <= prior {
			return store.ErrCorrupt
		}
		prior = k.Rule.String()
	}
	return nil
}

// BodyCarry は確定順の再送拒否・受理枠集合。所有板・キーは回収正本から継承する。
type BodyCarry struct {
	Dedups     []DedupCarry
	Rates      []RateCarry
	Retirement *BodyCarryRetirement `json:"retirement,omitempty"`
}

// Digest は署名済み回収正本と同じ順序・byte契約で集合を検算する。
func (v BodyCarry) Digest(floor domain.Time) (domain.Hash, domain.Hash, error) {
	if len(v.Dedups) > store.MaxPackEntries || len(v.Rates) > store.MaxPackEntries {
		return domain.Hash{}, domain.Hash{}, store.ErrCorrupt
	}
	dedup, rates := sha256.New(), sha256.New()
	ids := map[domain.ID]bool{}
	var last domain.U64
	for _, c := range v.Dedups {
		d, e := c.Validate(floor)
		if e != nil || ids[c.ID] || d.Seq <= last {
			return domain.Hash{}, domain.Hash{}, store.ErrCorrupt
		}
		ids[c.ID], last = true, d.Seq
		raw, _ := base64.StdEncoding.DecodeString(c.Entry)
		dedup.Write(raw)
	}
	ids = map[domain.ID]bool{}
	var number uint32
	var at domain.Time
	for _, c := range v.Rates {
		if c.Validate() != nil || ids[c.ID] || c.Number <= number || c.At < at {
			return domain.Hash{}, domain.Hash{}, store.ErrCorrupt
		}
		ids[c.ID], number, at = true, c.Number, c.At
		raw, _ := json.Marshal(c)
		rates.Write(raw)
		rates.Write([]byte{'\n'})
	}
	var d, r domain.Hash
	copy(d[:], dedup.Sum(nil))
	copy(r[:], rates.Sum(nil))
	return d, r, nil
}

// ExportBodyCarry は照合済み元frameから本文なしの集合を作る。回収証明と同じfloor/atを渡す。
func (p *PostingLog) ExportBodyCarry(floor, at domain.Time) (BodyCarry, error) {
	return p.exportBodyCarry(p.records(), floor, at)
}

func (p *PostingLog) exportBodyCarry(records []store.ThreadRecord, floor, at domain.Time) (BodyCarry, error) {
	out := BodyCarry{Dedups: []DedupCarry{}, Rates: []RateCarry{}}
	for _, r := range records {
		if r.Dedup != nil && r.Dedup.Expires > floor {
			raw, e := store.EncodeRejectedDedup(store.PackDedup{ID: r.ID, Seq: r.Seq, Committed: r.Committed, Value: *r.Dedup}, r.Seq, floor)
			if e != nil {
				return out, e
			}
			out.Dedups = append(out.Dedups, DedupCarry{r.ID, r.Seq, base64.StdEncoding.EncodeToString(raw)})
		}
		if r.Type != "create" && r.Type != "append" || r.Committed <= at-3660e9 {
			continue
		}
		entry, ok := p.proposals[r.ID]
		if !ok {
			return out, ErrEvidenceGap
		}
		raw, e := entry.decodeFrame()
		if e != nil || sha256.Sum256(raw) != r.FrameSHA {
			return out, ErrEvidenceGap
		}
		v, e := FrameRateRecord(raw)
		if e != nil {
			return out, e
		}
		out.Rates = append(out.Rates, RateCarry{v.ID, v.PostNumber, v.At, v.At + 3660e9, v.Keys})
	}
	_, _, e := out.Digest(floor)
	return out, e
}

// UseBodyCarry は独立保存された索引を署名へ照合し、回収済み所有者の再送索引へ接続する。
// 元確定操作の監査照合は維持し、非公開証拠を回収する権限は与えない。
func (p *PostingLog) UseBodyCarry(carry BodyCarry) error {
	if p.reclaimed == nil || carry.Retirement != nil {
		return ErrEvidenceGap
	}
	proof := p.reclaimed.proof
	d, r, e := carry.Digest(proof.Floor)
	if e != nil || d != proof.DedupSHA || r != proof.RateSHA {
		return ErrEvidenceGap
	}
	records := map[domain.ID]int{}
	for i, r := range p.reclaimed.records {
		records[r.ID] = i
	}
	dedups := map[domain.ID]store.PackDedup{}
	for _, c := range carry.Dedups {
		d, e := c.Validate(proof.Floor)
		i, ok := records[c.ID]
		if e != nil || !ok || p.reclaimed.records[i].Seq != d.Seq || p.reclaimed.records[i].Committed != d.Committed {
			return ErrEvidenceGap
		}
		dedups[c.ID] = d
	}
	for _, c := range carry.Rates {
		i, ok := records[c.ID]
		if !ok || p.reclaimed.records[i].Committed != c.At {
			return ErrEvidenceGap
		}
	}
	for i, r := range p.reclaimed.records {
		p.reclaimed.records[i].Dedup = nil
		if d, ok := dedups[r.ID]; ok {
			value := d.Value
			p.reclaimed.records[i].Dedup = &value
		}
	}
	owned := BodyCarry{Dedups: append([]DedupCarry{}, carry.Dedups...), Rates: append([]RateCarry{}, carry.Rates...)}
	for i := range owned.Rates {
		owned.Rates[i].Keys = append([]domain.RateKey{}, owned.Rates[i].Keys...)
	}
	p.reclaimed.carry = &owned
	return nil
}
