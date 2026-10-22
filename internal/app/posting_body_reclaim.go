// 公開本体の回収証明を署名し、非公開の受理記録から本文なし状態だけを復旧する。
package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// BodyReclamation は公開用コピーだけの回収証明。本文・タイトル・元IPを含まない。
type BodyReclamation struct {
	Schema     uint32                 `json:"schema"`
	Deletion   domain.ID              `json:"deletion_id"`
	Owner      domain.ID              `json:"board_id"`
	Key        domain.U64             `json:"thread_key"`
	Kind       string                 `json:"kind"`
	At         domain.Time            `json:"created_at_ns"`
	Floor      domain.Time            `json:"dedup_floor_ns"`
	Sequence   domain.U64             `json:"source_seq"`
	Expires    domain.Time            `json:"thread_expires_at_ns"`
	Policy     domain.Policy          `json:"policy"`
	After      domain.After           `json:"after"`
	RecordsSHA domain.Hash            `json:"records_sha256"`
	DedupSHA   domain.Hash            `json:"dedup_sha256"`
	RateSHA    domain.Hash            `json:"rate_sha256"`
	Files      []store.BodySourceFile `json:"files"`
	Signature  string                 `json:"signature"`
}

// CarryAt は時計逆行に備えて全受理枠を引き継ぐ境界を返す。
func (v BodyReclamation) CarryAt() domain.Time { return 0 }

type reclaimedBody struct {
	proof   BodyReclamation
	records []store.ThreadRecord
	carry   *BodyCarry
}

// Verify は所有単位・固定境界・canonical署名を検証する。元受理記録の照合は復旧時に別途行う。
func (v BodyReclamation) Verify(key ed25519.PublicKey) error {
	if v.Schema != 2 || v.Deletion == (domain.ID{}) || v.Owner == (domain.ID{}) || v.Key == 0 || v.Sequence == 0 || v.Sequence > store.MaxPackEntries || v.At <= 0 || v.Floor < 0 || v.Expires <= 0 || v.Policy.Validate() != nil || v.After.BumpValue == 0 || v.RecordsSHA == (domain.Hash{}) || v.DedupSHA == (domain.Hash{}) || v.RateSHA == (domain.Hash{}) || store.ValidateBodySourceFiles(v.Files) != nil {
		return store.ErrCorrupt
	}
	if v.Kind == "hide" {
		if v.After.State != "hidden" {
			return store.ErrCorrupt
		}
	} else if v.Kind != "pressure" && (v.Kind != "expire" || v.At < v.Expires) {
		return store.ErrCorrupt
	}
	signature, e := base64.RawStdEncoding.Strict().DecodeString(v.Signature)
	if e != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != v.Signature || len(key) != ed25519.PublicKeySize {
		return store.ErrCorrupt
	}
	v.Signature = ""
	raw, e := json.Marshal(v)
	if e != nil || !ed25519.Verify(key, append([]byte("oimo/body-reclamation/v1\x00"), raw...), signature) {
		return store.ErrCorrupt
	}
	return nil
}

// PrepareBodyReclamation は回収前の確定状態と参照ファイルを照合し、元期限を保った署名を作る。
func (p *PostingLog) PrepareBodyReclamation(ctx context.Context, deletion domain.ID, kind string, at domain.Time, key ed25519.PrivateKey) (BodyReclamation, error) {
	if p.stopped || p.thread == nil || len(key) != ed25519.PrivateKeySize {
		return BodyReclamation{}, ErrEvidenceGap
	}
	s := p.thread.State()
	records := p.thread.Records()
	if len(records) == 0 || at < records[len(records)-1].Committed {
		return BodyReclamation{}, ErrEvidenceGap
	}
	v := BodyReclamation{Schema: 2, Deletion: deletion, Owner: p.owner, Key: domain.U64(p.key), Kind: kind, At: at, Floor: p.thread.DedupRetentionFloor(), Sequence: s.Revision, Expires: s.Expires, Policy: s.Policy, After: s.After}
	var e error
	v.Files, e = p.thread.BodySourceFiles(ctx)
	if e != nil {
		return v, e
	}
	v.RecordsSHA = bodyRecordsSHA(records)
	v.DedupSHA, v.RateSHA, e = p.bodyCarrySHA(records, v.Floor, v.CarryAt())
	if e != nil {
		return v, e
	}
	raw, e := json.Marshal(v)
	if e != nil {
		return v, e
	}
	v.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("oimo/body-reclamation/v1\x00"), raw...)))
	return v, v.Verify(key.Public().(ed25519.PublicKey))
}

func bodyRecordsSHA(records []store.ThreadRecord) domain.Hash {
	h := sha256.New()
	for _, r := range records {
		r.Dedup = nil
		raw, _ := json.Marshal(r)
		h.Write(raw)
		h.Write([]byte{'\n'})
	}
	var out domain.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// bodyCarrySHA は再送拒否と受理枠の本文なし集合を、確定順のdigestへ束縛する。
func (p *PostingLog) bodyCarrySHA(records []store.ThreadRecord, floor, at domain.Time) (domain.Hash, domain.Hash, error) {
	carry, e := p.exportBodyCarry(records, floor, at)
	if e != nil {
		return domain.Hash{}, domain.Hash{}, e
	}
	return carry.Digest(floor)
}

// RetireBody は先行証明をSyncした所有者がwriterを閉じ、以後の公開・変更を拒否する。
func (p *PostingLog) RetireBody(v BodyReclamation) error {
	if p.reclaimed != nil {
		if reflect.DeepEqual(p.reclaimed.proof, v) {
			return nil
		}
		return ErrEvidenceGap
	}
	if p.thread == nil || p.owner != v.Owner || domain.U64(p.key) != v.Key || p.thread.State().Revision != v.Sequence || bodyRecordsSHA(p.thread.Records()) != v.RecordsSHA {
		return ErrEvidenceGap
	}
	records := p.thread.Records()
	for i := range records {
		if records[i].Dedup != nil && records[i].Dedup.Expires <= v.Floor {
			records[i].Dedup = nil
		}
	}
	p.RestoreExpired()
	if e := p.thread.Close(); e != nil {
		p.stopWriter()
		return e
	}
	p.thread = nil
	p.reclaimed = &reclaimedBody{proof: v, records: records}
	return nil
}

// Reclaimed は公開本体の参照を失ったことが検証済みの状態だけを表す。
func (p *PostingLog) Reclaimed() bool { return p.reclaimed != nil }

func (p *PostingLog) records() []store.ThreadRecord {
	if p.thread != nil {
		return p.thread.Records()
	}
	if p.reclaimed != nil {
		return p.reclaimed.records
	}
	return nil
}

func (p *PostingLog) firstRecord() (store.ThreadRecord, bool) {
	if p.thread != nil {
		return p.thread.FirstRecord()
	}
	if p.reclaimed != nil && len(p.reclaimed.records) > 0 {
		return p.reclaimed.records[0], true
	}
	return store.ThreadRecord{}, false
}

func (p *PostingLog) openReclaimed(v BodyReclamation, decisions map[domain.ID]postingDecision, public ed25519.PublicKey) error {
	if e := v.Verify(public); e != nil {
		return e
	}
	if v.Owner != p.owner || uint64(v.Key) != p.key {
		return ErrEvidenceGap
	}
	accepted := []proposalEntry{}
	for id, d := range decisions {
		entry, ok := p.proposals[id]
		if !ok || !d.matches(entry.payload, entry.event) {
			return ErrEvidenceGap
		}
		if d.Outcome == "accepted" {
			accepted = append(accepted, entry)
		}
	}
	if uint64(len(accepted)) != uint64(v.Sequence) || len(accepted) > store.MaxPackEntries {
		return ErrEvidenceGap
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].payload.ThreadSeq < accepted[j].payload.ThreadSeq })
	builder := store.NewPackBuilder(nil)
	for _, entry := range accepted {
		raw, e := entry.decodeFrame()
		if e != nil || sha256.Sum256(raw) != entry.payload.FrameSHA {
			return ErrEvidenceGap
		}
		frame, n, e := store.ReadFrame(bytes.NewReader(raw))
		if e != nil || n != int64(len(raw)) {
			return ErrEvidenceGap
		}
		if e = builder.Apply(frame); e != nil {
			return e
		}
	}
	s := builder.Snapshot(p.owner, p.key, 1, v.Floor)
	if s.State == nil || s.State.Revision != v.Sequence || s.State.Expires != v.Expires || !reflect.DeepEqual(s.State.Policy, v.Policy) || !reflect.DeepEqual(s.State.After, v.After) {
		return ErrEvidenceGap
	}
	records := builder.Records()
	if bodyRecordsSHA(records) != v.RecordsSHA {
		return ErrEvidenceGap
	}
	for i := range records {
		if records[i].Dedup != nil && records[i].Dedup.Expires <= v.Floor {
			records[i].Dedup = nil
		}
	}
	d, r, e := p.bodyCarrySHA(records, v.Floor, v.CarryAt())
	if e != nil || d != v.DedupSHA || r != v.RateSHA {
		return errors.Join(ErrEvidenceGap, e)
	}
	p.reclaimed = &reclaimedBody{proof: v, records: records}
	p.RestoreExpired()
	return p.reconcile(decisions, v.At)
}
